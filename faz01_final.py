# FAZ 1 — Güvenlik Olay Özeti

olaylar = [
    {"aciklama": "Başarısız SSH girişi", "skor": 8.5},
    {"aciklama": "Yetkisiz dosya erişimi", "skor": 6.2},
    {"aciklama": "Disk doluluk uyarısı", "skor": 3.1},
    {"aciklama": "Admin yetkisi alındı", "skor": 9.1},
]

def seviye_belirle(skor):
    """Skora göre seviye belirle"""
    if skor >= 9.0:
        return "KRİTİK"
    elif skor >= 7.0:
        return "YÜKSEK"
    elif skor >= 4.0:
        return "ORTA"
    else:
        return "DÜŞÜK"

print("=" * 50)
print("   GÜVENLİK OLAY ANALİZİ — FAZ 1")
print("=" * 50)

for olay in olaylar:
    seviye = seviye_belirle(olay["skor"])
    print(f"[{seviye:8}] {olay['aciklama']:<35} Skor: {olay['skor']}")

print("=" * 50)
print(f"Toplam olay: {len(olaylar)}")