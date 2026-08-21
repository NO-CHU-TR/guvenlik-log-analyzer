"""
Güvenlik Olayı Analizcisi
Olayları analiz edip puanlar.
"""

from .severity import seviye_belirle


def analiz_et(olay):
    """
    Bir olayı analiz edip seviye ve ek info ekler.
    
    Args:
        olay (dict): aciklama, skor anahtarlarını içermeli
    
    Returns:
        dict: olay + seviye + sonuç
    """
    skor = olay.get("skor", 0)
    seviye = seviye_belirle(skor)
    
    return {
        **olay,  # Orijinal verileri koru
        "seviye": seviye,
        "tehlike": "Yüksek" if skor >= 7 else "Normal"
    }


def toplu_analiz(olaylar):
    """
    Olay listesini analiz eder.
    
    Args:
        olaylar (list): dict listesi
    
    Returns:
        list: analiz edilmiş olaylar
    """
    return [analiz_et(olay) for olay in olaylar]