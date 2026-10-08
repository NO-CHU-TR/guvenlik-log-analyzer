"""
PHASE 7 — HTML Report
Creates professional HTML report from security events.
"""

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.reporters.html_reporter import rapor_olustur

print("Processing logs...\n")

# Collect → Parse → Score
olaylar = hesapla_toplu(parse_toplu(topla(adet=200)))

# Generate HTML report
rapor_olustur(olaylar, "rapor.html")

print(f"📊 {len(olaylar)} olay işlendi")
print("🌐 rapor.html dosyasını tarayıcıda aç!")