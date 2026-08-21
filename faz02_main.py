"""
PHASE 2 — Modular Structure
Importing functions from separate modules.
"""

from src.scoring.severity import seviye_belirle, renkli_seviye
from src.scoring.event_analyzer import toplu_analiz
from src.scoring.filters import kritik_olaylari_filtrele, aciklama_araması
from src.utils.formatter import table_header, event_row, summary_print


# Test data
olaylar = [
    {"aciklama": "Başarısız SSH girişi", "skor": 8.5},
    {"aciklama": "Yetkisiz dosya erişimi", "skor": 6.2},
    {"aciklama": "Disk doluluk uyarısı", "skor": 3.1},
    {"aciklama": "Admin yetkisi alındı", "skor": 9.1},
]

# Analyze
analysis_result = toplu_analiz(olaylar)

# Print with new formatter
table_header("SECURITY EVENT ANALYSIS — PHASE 2 (MODULAR)")

for event in analysis_result:
    print(event_row(event))

summary_print(analysis_result)

# Filter critical events
kritikler = kritik_olaylari_filtrele(analysis_result)
print(f"\n🔴 CRITICAL EVENTS ({len(kritikler)}):")
for event in kritikler:
    print(f"  → {event['aciklama']} (Score: {event['skor']})")

# Search for "giriş"
giris_olaylari = aciklama_araması(analysis_result, "giriş")
print(f"\n🔍 EVENTS WITH 'GİRİŞ' ({len(giris_olaylari)}):")
for event in giris_olaylari:
    print(f"  → {event['aciklama']}")