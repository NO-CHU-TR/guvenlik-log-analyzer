"""
Windows Event Log Collector
Collects security logs and returns as dict list.
"""

import win32evtlog

# Tracked Event IDs and descriptions
SECURITY_IDS = {
    4624: "Başarılı giriş",
    4625: "Başarısız giriş",
    4648: "Açık kimlik bilgisiyle giriş",
    4720: "Yeni kullanıcı oluşturuldu",
    4732: "Gruba üye eklendi",
    4698: "Zamanlanmış görev oluşturuldu",
    7045: "Yeni servis kuruldu",
}


def topla(adet=200):
    """
    Collects security events from last N records.
    
    Args:
        adet (int): Number of records to scan
        
    Returns:
        list: Security events (list of dicts)
    """
    sunucu = None  # None = local computer
    islem = win32evtlog.OpenEventLog(sunucu, "Security")
    bayraklar = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)

    sonuclar = []
    islenen = 0

    try:
        while islenen < adet:
            kayitlar = win32evtlog.ReadEventLog(islem, bayraklar, 0)
            if not kayitlar:
                break

            for kayit in kayitlar:
                islenen += 1
                gercek_id = kayit.EventID & 0xFFFF

                if gercek_id in SECURITY_IDS:
                    sonuclar.append({
                        "event_id": gercek_id,
                        "aciklama": SECURITY_IDS[gercek_id],
                        "zaman": str(kayit.TimeGenerated),
                        "kaynak": kayit.SourceName,
                        "mesaj": (list(kayit.StringInserts)
                                  if kayit.StringInserts else [])
                    })
    finally:
        win32evtlog.CloseEventLog(islem)

    return sonuclar