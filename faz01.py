# Değişkenler — farklı veri tipleri

isim = "Güvenlik Log Analyzer"   # str (metin)
versiyon = 1                      # int (tam sayı)
skor = 7.5                        # float (ondalıklı)
aktif = True                      # bool (doğru/yanlış)

print("Uygulama Adı:", isim)
print("Versiyon:", versiyon)
print("Risk Skoru:", skor)
print("Aktif mi:", aktif)

# Tip öğrenmek
print("İsim tipi:", type(isim))
print("Skor tipi:", type(skor))

# Güvenlik skoru değerlendirme

skor = 8.5

if skor >= 9.0:
    seviye = "KRİTİK"
elif skor >= 7.0:
    seviye = "YÜKSEK"
elif skor >= 4.0:
    seviye = "ORTA"
else:
    seviye = "DÜŞÜK"

print(f"Skor: {skor} → Seviye: {seviye}")

# Güvenlik olayları listesi

olaylar = [
    "Başarısız giriş denemesi",
    "Yetkisiz dosya erişimi",
    "Şüpheli ağ trafiği",
    "Servis başlatma hatası"
]

print("=== TESPİT EDİLEN OLAYLAR ===")
for i, olay in enumerate(olaylar, start=1):
    print(f"{i}. {olay}")

print(f"\nToplam olay sayısı: {len(olaylar)}")