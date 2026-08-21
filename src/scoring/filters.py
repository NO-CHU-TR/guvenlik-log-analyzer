"""
Olay Filtreleme Fonksiyonları
Belirli kriterlere göre olayları filtreler.
"""


def kritik_olaylari_filtrele(olaylar):
    """Sadece kritik olayları döndür."""
    return [o for o in olaylar if o.get("seviye") == "KRİTİK"]


def yuksek_skorlu_olaylari_getir(olaylar, min_skor=7.0):
    """Belirli skor üstündeki olayları döndür."""
    return [o for o in olaylar if o.get("skor", 0) >= min_skor]


def aciklama_araması(olaylar, anahtar):
    """Açıklamada anahtar kelime içeren olayları döndür."""
    anahtar = anahtar.lower()
    return [o for o in olaylar if anahtar in o.get("aciklama", "").lower()]