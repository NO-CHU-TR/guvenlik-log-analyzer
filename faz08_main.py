"""
PHASE 8 — Graphs & Visualization
Creates charts from security events.
"""

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.reporters.graph_reporter import grafikleri_olustur

print("Processing logs...\n")

# Collect → Parse → Score
olaylar = hesapla_toplu(parse_toplu(topla(adet=200)))

# Generate graphs
grafikleri_olustur(olaylar)

print(f"📊 {len(olaylar)} olay işlendi")
print("📈 grafikler.png dosyasını açarak görebilirsin!")