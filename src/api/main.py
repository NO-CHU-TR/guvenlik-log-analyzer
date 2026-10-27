"""
PHASE 12 — FastAPI: database endpoints
Serves security events and scan history from guvenlik.db.
"""

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from src.database.models import init_db, get_session, SecurityEvent, ScanResult

app = FastAPI(title="Güvenlik Log Analyzer API", version="1.0.0")

# Create the database engine once when the server starts
engine = init_db("guvenlik.db")


@app.get("/api/durum")
def durum():
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
                    "orta": t.orta_count,
                    "dusuk": t.dusuk_count,
                    "ort_skor": t.avg_score,
                }
                for t in taramalar
            ],
        }
    finally:
        session.close()


@app.get("/api/son-tarama")
def son_tarama():
    """Return the most recent scan summary (used by dashboard cards)."""
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

def _olay_dict(o: SecurityEvent) -> dict:
    return {
        "id": o.id,
        "event_id": o.event_id,
        "aciklama": o.aciklama,
        "skor": o.skor,
        "seviye": o.seviye,
        "kullanici": o.kullanici,
        "kaynak_ip": o.kaynak_ip,
        "zaman": o.zaman.isoformat(),
    }


@app.get("/api/olaylar")
def tum_olaylar(limit: int = 200):
    """Return the most recent Windows events (IaC findings excluded)."""
    session = get_session(engine)
    try:
        olaylar = (session.query(SecurityEvent)
                   .filter(SecurityEvent.event_id != 9000)
                   .order_by(SecurityEvent.zaman.desc())
                   .limit(limit)
                   .all())
        return {"adet": len(olaylar), "olaylar": [_olay_dict(o) for o in olaylar]}
    finally:
        session.close()


@app.get("/api/iac")
def iac_bulgulari():
    """Return Checkov IaC findings (stored with event_id 9000)."""
    session = get_session(engine)
    try:
        bulgular = (session.query(SecurityEvent)
                    .filter(SecurityEvent.event_id == 9000)
                    .order_by(SecurityEvent.skor.desc())
                    .all())
        return {"adet": len(bulgular), "bulgular": [_olay_dict(b) for b in bulgular]}
    finally:
        session.close()


@app.get("/api/istatistik")
def istatistik():
    """Event counts grouped by Event ID, user and source IP."""
    session = get_session(engine)
    try:
        temel = session.query(SecurityEvent).filter(SecurityEvent.event_id != 9000)

        def grupla(kolon, limit=10):
            satirlar = (temel.with_entities(kolon, func.count())
                        .filter(kolon.isnot(None), kolon != "", kolon != "-")
                        .group_by(kolon)
                        .order_by(func.count().desc())
                        .limit(limit)
                        .all())
            return [{"ad": str(ad), "adet": adet} for ad, adet in satirlar]

        olay_turleri = (temel.with_entities(SecurityEvent.event_id,
                                            SecurityEvent.aciklama, func.count())
                        .group_by(SecurityEvent.event_id, SecurityEvent.aciklama)
                        .order_by(func.count().desc())
                        .all())

        return {
            "toplam": temel.count(),
            "olay_turleri": [{"event_id": e, "aciklama": a, "adet": n}
                             for e, a, n in olay_turleri],
            "kullanicilar": grupla(SecurityEvent.kullanici),
            "ipler": grupla(SecurityEvent.kaynak_ip),
        }
    finally:
        session.close()


@app.get("/api/trend")
def trend():
    """Compare the last two scans (phase 10 logic as JSON)."""
    session = get_session(engine)
    try:
        son_iki = (session.query(ScanResult)
                   .order_by(ScanResult.scan_date.desc())
                   .limit(2)
                   .all())
        if len(son_iki) < 2:
            return {"var": False}

        simdi, onceki = son_iki
        d_kritik = simdi.kritik_count - onceki.kritik_count
        d_yuksek = simdi.yuksek_count - onceki.yuksek_count
        d_toplam = simdi.total_events - onceki.total_events

        if d_kritik > 0 or d_yuksek > 0:
            yorum = "Kötüleşiyor"
        elif d_toplam < 0:
            yorum = "İyileşiyor"
        else:
            yorum = "Stabil"

        return {"var": True, "toplam": d_toplam, "kritik": d_kritik,
                "yuksek": d_yuksek, "yorum": yorum}
    finally:
        session.close()


@app.get("/rapor")
def html_rapor():
    """Phase 7 HTML report."""
    return FileResponse("rapor.html")


@app.get("/grafik")
def grafik_png():
    """Phase 8 matplotlib charts."""
    return FileResponse("grafikler.png")


# Static files must be mounted AFTER all API routes.
# "/" serves frontend/index.html.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")