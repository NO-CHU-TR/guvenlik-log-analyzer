"""
Güvenlik Olayı Seviye Belirleyicisi
Skora göre olay seviyesini döndürür.
"""

def seviye_belirle(skor):
    """
    Risk skoruna göre seviyeyi belirler.
    
    Args:
        skor (float): 0-10 arası risk skoru
    
    Returns:
        str: "KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"
    """
    if skor >= 9.0:
        return "KRİTİK"
    elif skor >= 7.0:
        return "YÜKSEK"
    elif skor >= 4.0:
        return "ORTA"
    else:
        return "DÜŞÜK"


def renkli_seviye(seviye):
    """
    Seviyeyi terminale renkli yazdırmak için
    başına/sonuna özel karakter koyar.
    """
    renkler = {
        "KRİTİK": f"[KRİTİK]",
        "YÜKSEK": f"[YÜKSEK]",
        "ORTA": f"[ORTA]",
        "DÜŞÜK": f"[DÜŞÜK]"
    }
    return renkler.get(seviye, "[BİLİNMEYEN]")