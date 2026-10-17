"""
PHASE 12 — FastAPI: database endpoints
Serves security events and scan history from guvenlik.db.
"""

from fastapi import FastAPI
from src.database.models import init_db, get_session, SecurityEvent, ScanResult

app = FastAPI(title="Güvenlik Log Analyzer API", version="1.0.0")

# Create the database engine once when the server starts
engine = init_db("guvenlik.db")


@app.get("/")
def root():
    """Health check: confirms the API is running."""
    return {"durum": "çalışıyor", "versiyon": "1.0.0"}


@app.get("/api/olaylar/kritik")
def kritik_olaylar(limit: int = 20):
    """Return the most recent CRITICAL security events."""
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


@app.get("/api/gecmis")
def gecmis(limit: int = 20):
    """Return the most recent scan summaries."""
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
                    "ort_skor": t.avg_score,
                }
                for t in taramalar
            ],
        }
    finally:
        session.close()