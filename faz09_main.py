"""
PHASE 9 — Database Storage
Saves security events to SQLite database.
"""

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.database.models import init_db, get_session, SecurityEvent, ScanResult
from datetime import datetime

print("Processing logs...\n")

# Collect → Parse → Score
olaylar = hesapla_toplu(parse_toplu(topla(adet=200)))

# Initialize database
print("Initializing database...")
engine = init_db("guvenlik.db")
session = get_session(engine)

# Clear old data (for testing)
session.query(SecurityEvent).delete()
session.query(ScanResult).delete()

# Save events
print(f"Saving {len(olaylar)} events...")
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

session.commit()

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

print(f"✅ {len(olaylar)} olay veritabanına kaydedildi\n")

# Read and display
print("DATABASE CONTENTS:")
print("=" * 60)

events = session.query(SecurityEvent).all()
print(f"Total events: {len(events)}\n")

for event in events[:5]:
    print(f"[{event.seviye:<8}] {event.skor:.1f} | {event.aciklama} | {event.kullanici}")

print(f"\n... and {len(events) - 5} more events\n")

# Summary
scans = session.query(ScanResult).all()
latest = scans[-1] if scans else None
if latest:
    print(f"Latest Scan Summary:")
    print(f"  KRİTİK: {latest.kritik_count}")
    print(f"  YÜKSEK: {latest.yuksek_count}")
    print(f"  ORTA: {latest.orta_count}")
    print(f"  DÜŞÜK: {latest.dusuk_count}")
    print(f"  Ortalama Skor: {latest.avg_score:.2f}")

session.close()