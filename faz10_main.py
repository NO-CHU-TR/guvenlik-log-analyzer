"""
PHASE 10 — Trend Analysis
Analyzes trends from multiple database scans.
"""

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.database.models import init_db, get_session, SecurityEvent, ScanResult
from src.reporters.trend_reporter import trend_analizi
from datetime import datetime

print("Processing logs...\n")

# Collect → Parse → Score
olaylar = hesapla_toplu(parse_toplu(topla(adet=200)))

# Save to database
engine = init_db("guvenlik.db")
session = get_session(engine)

# Add events
for olay in olaylar:
    event = SecurityEvent(
        event_id=olay.get("event_id"),
        aciklama=olay.get("aciklama"),
        skor=olay.get("skor"),
        seviye=olay.get("seviye"),
        kullanici=olay.get("kullanici"),
        kaynak_ip=olay.get("kaynak_ip"),
        zaman=datetime.fromisoformat(olay.get("zaman", datetime.now().isoformat()))
    )
    session.add(event)

# Create scan summary
sayac = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
for olay in olaylar:
    seviye = olay.get("seviye", "DÜŞÜK")
    sayac[seviye] = sayac.get(seviye, 0) + 1

avg_score = sum(o.get("skor", 0) for o in olaylar) / len(olaylar) if olaylar else 0

scan = ScanResult(
    total_events=len(olaylar),
    kritik_count=sayac["KRİTİK"],
    yuksek_count=sayac["YÜKSEK"],
    orta_count=sayac["ORTA"],
    dusuk_count=sayac["DÜŞÜK"],
    avg_score=avg_score
)
session.add(scan)
session.commit()
session.close()

print(f"✅ {len(olaylar)} olay kaydedildi\n")

# Analyze trends
trend_analizi()