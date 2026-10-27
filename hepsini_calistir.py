"""
ONE-CLICK RUNNER — runs every phase up to 15 and opens the dashboard.

Steps:
  1. Scan Windows logs with GuvenlikAnalizcisi (phases 3-5, 9, 15)
  2. Terminal report (phase 6)
  3. HTML report + charts (phases 7-8)
  4. Trend analysis (phase 10)
  5. Checkov IaC findings (phase 11)
  6. FastAPI + dashboard (phases 12-14) in the browser
"""

import os
import threading
import webbrowser
from datetime import datetime

# Always work from the project folder (guvenlik.db, frontend/ are relative)
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from src.core.analyzer import GuvenlikAnalizcisi
from src.database.models import init_db, get_session, SecurityEvent
from src.reporters.terminal_reporter import rapor_yaz
from src.reporters.html_reporter import rapor_olustur
from src.reporters.graph_reporter import grafikleri_olustur
from src.reporters.trend_reporter import trend_analizi

PORT = 8000


def baslik(metin: str) -> None:
    print("\n" + "=" * 60)
    print(metin)
    print("=" * 60)


def db_olaylari() -> list:
    """Fallback: read Windows events from the database when a live scan fails."""
    session = get_session(init_db("guvenlik.db"))
    try:
        kayitlar = (session.query(SecurityEvent)
                    .filter(SecurityEvent.event_id != 9000)
                    .order_by(SecurityEvent.zaman.desc())
                    .limit(500)
                    .all())
        return [
            {
                "event_id": k.event_id,
                "aciklama": k.aciklama,
                "skor": k.skor,
                "seviye": k.seviye,
                "kullanici": k.kullanici,
                "kaynak_ip": k.kaynak_ip,
                "zaman": k.zaman.isoformat(),
            }
            for k in kayitlar
        ]
    finally:
        session.close()


def checkov_yukle() -> None:
    """Import Checkov findings, replacing the previous import (no duplicates)."""
    from faz11_main import CHECKOV_JSON, load_failed_checks, to_event

    if not os.path.exists(CHECKOV_JSON):
        print(f"⚠️ '{CHECKOV_JSON}' yok, IaC adımı atlandı.")
        return

    bulgular = load_failed_checks(CHECKOV_JSON)
    session = get_session(init_db("guvenlik.db"))
    try:
        session.query(SecurityEvent).filter(SecurityEvent.event_id == 9000).delete()
        for check in bulgular:
            session.add(to_event(check))
        session.commit()
        print(f"✅ {len(bulgular)} Checkov bulgusu kaydedildi")
    finally:
        session.close()


def adim(ad: str, fonksiyon, *args):
    """Run one step; a failure is reported but never stops the rest."""
    try:
        return fonksiyon(*args)
    except Exception as hata:
        print(f"❌ {ad} başarısız: {hata}")
        return None


def main():
    baslik("1) WINDOWS LOG TARAMASI")
    olaylar = adim("Tarama", GuvenlikAnalizcisi(tarama_adeti=200).tara)
    if olaylar is None:
        print("ℹ️ Canlı tarama yapılamadı (yönetici olarak çalıştır). "
              "Veritabanındaki eski olaylar kullanılıyor.")
        olaylar = db_olaylari()
    else:
        print(f"✅ {len(olaylar)} olay tarandı ve kaydedildi")

    baslik("2) TERMİNAL RAPORU")
    adim("Terminal raporu", rapor_yaz, olaylar)

    baslik("3) HTML RAPOR + GRAFİKLER")
    adim("HTML rapor", rapor_olustur, olaylar, "rapor.html")
    adim("Grafikler", grafikleri_olustur, olaylar)

    baslik("4) TREND ANALİZİ")
    adim("Trend", trend_analizi)

    baslik("5) CHECKOV IaC")
    adim("Checkov", checkov_yukle)

    baslik("6) DASHBOARD")
    url = f"http://127.0.0.1:{PORT}/"
    print(f"🌐 {url} açılıyor... (kapatmak için Ctrl+C)")
    threading.Timer(1.5, webbrowser.open, args=(url,)).start()

    import uvicorn
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    print(f"Güvenlik Log Analyzer — {datetime.now():%Y-%m-%d %H:%M}")
    main()
