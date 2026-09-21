"""
PHASE 6 — Terminal Report
Displays security events with rich formatting.
"""

from src.collectors.windows_log import topla
from src.parsers.event_parser import parse_toplu
from src.scoring.cvss_scorer import hesapla_toplu
from src.reporters.terminal_reporter import rapor_yaz

print("Processing logs...\n")
olaylar = hesapla_toplu(parse_toplu(topla(adet=200)))
rapor_yaz(olaylar)