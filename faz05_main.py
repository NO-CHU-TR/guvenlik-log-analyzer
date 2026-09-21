"""
PHASE 5 — CVSS Scoring
Assigns risk scores to parsed events.
"""

import json
from src.parsers.event_parser import parse_toplu
from src.collectors.windows_log import topla
from src.scoring.cvss_scorer import hesapla_toplu

print("Collecting logs...")
ham_olaylar = topla(adet=50)
print(f"  {len(ham_olaylar)} raw events")

print("Parsing...")
temiz_olaylar = parse_toplu(ham_olaylar)
print(f"  {len(temiz_olaylar)} events parsed")

print("Scoring...")
skorlu_olaylar = hesapla_toplu(temiz_olaylar)
print(f"  ✅ {len(skorlu_olaylar)} events scored\n")

# Save to JSON
cikti_dosyasi = "olaylar_scored.json"
with open(cikti_dosyasi, "w", encoding="utf-8") as f:
    json.dump(skorlu_olaylar, f, ensure_ascii=False, indent=2)

print(f"✅ Results saved to '{cikti_dosyasi}'")

# Show first 3 records with scores
print("\nFirst 3 records (with scores):")
for olay in skorlu_olaylar[:3]:
    print(f"\n[{olay['seviye']:<8}] Event {olay['event_id']}")
    print(f"  Açıklama: {olay['aciklama']}")
    print(f"  Skor: {olay['skor']:.1f}/10")
    print(f"  Kullanıcı: {olay.get('kullanici', '-')}")
    print(f"  IP: {olay.get('kaynak_ip', '-')}")