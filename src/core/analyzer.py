"""
Central analyzer class.
Coordinates the whole pipeline: collect -> parse -> score -> save.
"""

from datetime import datetime

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.database.models import init_db, get_session, SecurityEvent, ScanResult


class GuvenlikAnalizcisi:
    """Runs the full security analysis pipeline."""

    def __init__(self, tarama_adeti: int = 200):
        # Number of raw Windows events to read per scan
        self.tarama_adeti = tarama_adeti
        # Last scan results, kept in memory
        self._son_olaylar = []

    def tara(self) -> list:
        """Run one full scan and return the scored events."""
        # 1. Collect raw Windows events
        ham = topla(adet=self.tarama_adeti)

        # 2. Parse into clean dicts
        temiz = parse_toplu(ham)

        # 3. Assign risk scores and levels
        skorlu = hesapla_toplu(temiz)

        # 4. Save events and a scan summary to the database
        self._kaydet(skorlu)

        self._son_olaylar = skorlu
        return skorlu

    def kritikleri_getir(self, limit: int = 20) -> list:
        """Return critical events from the last scan."""
        kritikler = [o for o in self._son_olaylar if o.get("seviye") == "KRİTİK"]
        return kritikler[:limit]

    def ozet_uret(self, olaylar: list) -> dict:
        """Count events per severity level."""
        sayac = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
        for olay in olaylar:
            seviye = olay.get("seviye", "DÜŞÜK")
            sayac[seviye] = sayac.get(seviye, 0) + 1
        return sayac

    def _kaydet(self, olaylar: list) -> None:
        """Write events and a scan summary to guvenlik.db."""
        engine = init_db("guvenlik.db")
        session = get_session(engine)
        try:
            for olay in olaylar:
                session.add(SecurityEvent(
                    event_id=olay.get("event_id"),
                    aciklama=olay.get("aciklama"),
                    skor=olay.get("skor"),
                    seviye=olay.get("seviye"),
                    kullanici=olay.get("kullanici"),
                    kaynak_ip=olay.get("kaynak_ip"),
                    zaman=datetime.fromisoformat(
                        olay.get("zaman") or datetime.now().isoformat()
                    ),
                ))

            ozet = self.ozet_uret(olaylar)
            session.add(ScanResult(
                total_events=len(olaylar),
                kritik_count=ozet["KRİTİK"],
                yuksek_count=ozet["YÜKSEK"],
                orta_count=ozet["ORTA"],
                dusuk_count=ozet["DÜŞÜK"],
                avg_score=(sum(o.get("skor", 0) for o in olaylar) / len(olaylar)
                           if olaylar else 0),
            ))
            session.commit()
        finally:
            session.close()