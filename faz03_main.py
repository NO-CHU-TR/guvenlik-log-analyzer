"""
PHASE 3 — Windows Log Reading
Testing with mock data.
"""

from src.scoring.event_analyzer import toplu_analiz
from src.utils.formatter import table_header, summary_print

# Mock data (test için)
olaylar = [
    {"event_id": 4625, "aciklama": "Başarısız giriş", "zaman": "2026-01-15 03:42:18", "kaynak": "Security", "mesaj": []},
    {"event_id": 4624, "aciklama": "Başarılı giriş", "zaman": "2026-01-15 03:41:00", "kaynak": "Security", "mesaj": []},
    {"event_id": 4720, "aciklama": "Yeni kullanıcı oluşturuldu", "zaman": "2026-01-14 15:30:22", "kaynak": "Security", "mesaj": []},
    {"event_id": 4625, "aciklama": "Başarısız giriş", "zaman": "2026-01-14 14:15:00", "kaynak": "Security", "mesaj": []},
    {"event_id": 4698, "aciklama": "Zamanlanmış görev oluşturuldu", "zaman": "2026-01-14 10:00:00", "kaynak": "Security", "mesaj": []},
]

print("✅ Test verileri yüklendi!\n")

# Add scores
for olay in olaylar:
    if olay['event_id'] == 4625:
        olay['skor'] = 8.5
    elif olay['event_id'] == 4624:
        olay['skor'] = 2.0
    elif olay['event_id'] == 4720:
        olay['skor'] = 8.0
    elif olay['event_id'] == 4698:
        olay['skor'] = 7.5
    else:
        olay['skor'] = 5.0

# Analyze
analiz = toplu_analiz(olaylar)

table_header("SON OLAYLAR")
for olay in analiz[:10]:
    print(f"[{olay['event_id']}] {olay['aciklama']:<35} | {olay['zaman']}")

summary_print(analiz)