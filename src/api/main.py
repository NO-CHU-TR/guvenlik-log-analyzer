"""
PHASE 12-18 — FastAPI: database endpoints, scan trigger, AI interpretation
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from src.database.models import init_db, get_session, SecurityEvent, ScanResult
from src.ai.interpreter import yorumla
from src.core.analyzer import GuvenlikAnalizcisi

app = FastAPI(title="Güvenlik Log Analyzer API", version="1.0.0")

engine = init_db("guvenlik.db")


@app.get("/api/durum")
def durum():
    return {"durum": "çalışıyor", "versiyon": "1.0.0"}


@app.get("/api/son-tarama")
def son_tarama():
    session = get_session(engine)
    try:
        son = (session.query(ScanResult)
               .order_by(ScanResult.scan_date.desc())
               .first())
        if son is None:
            return {"var": False}
        return {
            "var": True,
            "tarih": son.scan_date.isoformat(),
            "toplam": son.total_events,
            "kritik": son.kritik_count,
            "yuksek": son.yuksek_count,
            "orta": son.orta_count,
            "dusuk": son.dusuk_count,
            "ort_skor": son.avg_score,
        }
    finally:
        session.close()


@app.get("/api/gecmis")
def gecmis(limit: int = 20):
    session = get_session(engine)
    try:
        taramalar = (session.query(ScanResult)
                     .order_by(ScanResult.scan_date.desc())
                     .limit(limit)
                     .all())
        return {
            "tarama_sayisi": len(taramalar),
            "taramalar": [
                {
                    "id": t.id,
                    "tarih": t.scan_date.isoformat(),
                    "toplam": t.total_events,
                    "kritik": t.kritik_count,
                    "yuksek": t.yuksek_count,
                    "orta": t.orta_count,
                    "dusuk": t.dusuk_count,
                    "ort_skor": t.avg_score,
                }
                for t in taramalar
            ],
        }
    finally:
        session.close()


@app.get("/api/olaylar/kritik")
def kritik_olaylar(limit: int = 20):
    session = get_session(engine)
    try:
        olaylar = (session.query(SecurityEvent)
                   .filter(SecurityEvent.seviye == "KRİTİK")
                   .order_by(SecurityEvent.zaman.desc())
                   .limit(limit)
                   .all())
        return {
            "adet": len(olaylar),
            "olaylar": [
                {
                    "id": o.id,
                    "event_id": o.event_id,
                    "aciklama": o.aciklama,
                    "skor": o.skor,
                    "kullanici": o.kullanici,
                    "kaynak_ip": o.kaynak_ip,
                    "zaman": o.zaman.isoformat(),
                }
                for o in olaylar
            ],
        }
    finally:
        session.close()


@app.get("/api/olaylar/{olay_id}/yorumla")
def olay_yorumla(olay_id: int):
    session = get_session(engine)
    try:
        olay = session.query(SecurityEvent).filter(SecurityEvent.id == olay_id).first()
        if olay is None:
            return {"hata": "Olay bulunamadı", "id": olay_id}
        yorum = yorumla({
            "aciklama": olay.aciklama,
            "event_id": olay.event_id,
            "skor": olay.skor,
            "seviye": olay.seviye,
            "kullanici": olay.kullanici,
            "kaynak_ip": olay.kaynak_ip,
        })
        return {"id": olay.id, "aciklama": olay.aciklama, "yorum": yorum}
    finally:
        session.close()


@app.post("/api/tara")
def tara_calistir(ai_adet: int = 3):
    """Scan Windows logs now, then ask the AI about the most risky stored events."""
    try:
        analizci = GuvenlikAnalizcisi(tarama_adeti=200)
        olaylar = analizci.tara()
    except Exception as hata:
        return {
            "basarili": False,
            "hata": f"Tarama yapılamadı: {hata}. Sunucu yönetici olarak çalışmalı.",
        }

    session = get_session(engine)
    try:
        riskli = (session.query(SecurityEvent)
                  .filter(SecurityEvent.event_id != 9000)
                  .order_by(SecurityEvent.skor.desc())
                  .limit(ai_adet)
                  .all())
        yorumlar = [
            {
                "id": o.id,
                "aciklama": o.aciklama,
                "skor": o.skor,
                "yorum": yorumla({
                    "aciklama": o.aciklama,
                    "event_id": o.event_id,
                    "skor": o.skor,
                    "seviye": o.seviye,
                    "kullanici": o.kullanici,
                    "kaynak_ip": o.kaynak_ip,
                }),
            }
            for o in riskli
        ]
    finally:
        session.close()

    return {
        "basarili": True,
        "toplam": len(olaylar),
        "ozet": analizci.ozet_uret(olaylar),
        "yorumlar": yorumlar,
    }


# Static files must be mounted LAST
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")