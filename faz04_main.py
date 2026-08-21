"""
PHASE 4 — Log Parse
Converts raw logs to clean JSON format.
"""

import json
from src.parsers.event_parser import parse_toplu

# Mock data
ham_olaylar = [
    {
        "event_id": 4625,
        "aciklama": "Başarısız giriş",
        "zaman": "2026-01-15 03:42:18+00:00",
        "kaynak": "Security",
        "mesaj": ["-", "-", "WORKGROUP", "0x0", "0", "TANITILMAMIS", "NtLmSsp", 
                  "WIN-TEST", "admin", "WORKGROUP", "192.168.1.105", "0", "", "", "", "", ""]
    },
    {
        "event_id": 4624,
        "aciklama": "Başarılı giriş",
        "zaman": "2026-01-15 03:41:00+00:00",
        "kaynak": "Security",
        "mesaj": ["-", "-", "WORKGROUP", "0x0", "0", "TANITILMAMIS", "NtLmSsp",
                  "WIN-TEST", "oyku", "WORKGROUP", "192.168.1.100", "0", "", "", "", "", ""]
    },
    {
        "event_id": 4720,
        "aciklama": "Yeni kullanıcı oluşturuldu",
        "zaman": "2026-01-14 15:30:22+00:00",
        "kaynak": "Security",
        "mesaj": ["yeni_kullanici", "", "", "", "admin", "", "", "", "", "", "", ""]
    },
]

print("Parsing mock data...")
temiz_olaylar = parse_toplu(ham_olaylar)
print(f"  {len(temiz_olaylar)} events parsed")

# Save to JSON
cikti_dosyasi = "olaylar.json"
with open(cikti_dosyasi, "w", encoding="utf-8") as f:
    json.dump(temiz_olaylar, f, ensure_ascii=False, indent=2)

print(f"\n✅ Results saved to '{cikti_dosyasi}'")

# Show first 3 records
print("\nFirst 3 records:")
for olay in temiz_olaylar[:3]:
    print(json.dumps(olay, ensure_ascii=False, indent=2))