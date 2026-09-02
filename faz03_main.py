"""
PHASE 3 — Windows Log Reading
Reading real Windows Event Logs.
"""

from src.collectors.windows_log import topla
from src.scoring.event_analyzer import toplu_analiz
from src.utils.formatter import table_header, summary_print

print("Reading logs...")
olaylar = topla(adet=50)  # Gerçek veri oku!
print(f"✅ {len(olaylar)} events found!\n")

if olaylar:
    # Add scores
    for olay in olaylar:
        if olay['event_id'] == 4625:
            olay['skor'] = 8.5
        elif olay['event_id'] == 4624:
            olay['skor'] = 2.0
        elif olay['event_id'] == 4720:
            olay['skor'] = 8.0
        else:
            olay['skor'] = 5.0

    # Analyze
    analiz = toplu_analiz(olaylar)

    table_header("SON OLAYLAR")
    for olay in analiz[:10]:
        print(f"[{olay['event_id']}] {olay['aciklama']:<35} | {olay['zaman']}")

    summary_print(analiz)
else:
    print("⚠️ Hiç log bulunamadı.")