"""
PHASE 15 — OOP & Layered Architecture
Runs the analyzer class instead of repeating the pipeline steps.
"""

from src.core.analyzer import GuvenlikAnalizcisi

analizci = GuvenlikAnalizcisi(tarama_adeti=200)

print("Tarama başlıyor...")
olaylar = analizci.tara()
print(f"✅ {len(olaylar)} olay tarandı ve kaydedildi\n")

kritikler = analizci.kritikleri_getir()
print(f"Kritik olay sayısı: {len(kritikler)}")

for olay in kritikler[:5]:
    print(f"  [{olay['seviye']}] {olay['skor']} | {olay['aciklama']}")