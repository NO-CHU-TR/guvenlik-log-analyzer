"""
PHASE 4 — Log Parse
Converts raw logs to clean JSON format.
"""

import json
from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu

print("Collecting logs...")
ham_olaylar = topla(adet=50)
print(f"  {len(ham_olaylar)} raw events found")

print("Parsing...")
temiz_olaylar = parse_toplu(ham_olaylar)
print(f"  {len(temiz_olaylar)} events parsed\n")

# Save to JSON
cikti_dosyasi = "olaylar.json"
with open(cikti_dosyasi, "w", encoding="utf-8") as f:
    json.dump(temiz_olaylar, f, ensure_ascii=False, indent=2)

print(f"✅ Results saved to '{cikti_dosyasi}'")

# Show first 3 records
print("\nFirst 3 records:")
for olay in temiz_olaylar[:3]:
    print(json.dumps(olay, ensure_ascii=False, indent=2))