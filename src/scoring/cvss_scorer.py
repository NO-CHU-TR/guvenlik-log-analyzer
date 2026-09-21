"""
CVSS Scoring Module
Assigns risk scores (0-10) to security events.
"""


# Base scores for each event type
EVENT_SCORES = {
    4625: 8.5,   # Failed logon - someone trying to break in
    4624: 2.0,   # Successful logon - normal activity
    4648: 7.0,   # Explicit credentials used - suspicious
    4720: 7.5,   # New user created - potential backdoor
    4732: 6.5,   # User added to group - privilege escalation
    4698: 7.0,   # Scheduled task created - automation abuse
    7045: 8.0,   # New service installed - could be malware
}


def hesapla_skor(olay: dict) -> float:
    """
    Calculate risk score for a single event.
    
    Args:
        olay: Clean event dict from parser
        
    Returns:
        float: Risk score 0-10
    """
    event_id = olay.get("event_id", 0)
    
    # Get base score for this event type
    skor = EVENT_SCORES.get(event_id, 5.0)  # Default 5.0 if unknown
    
    # Adjust score based on additional factors
    skor = _ayarla_ip(skor, olay)
    skor = _ayarla_kullanici(skor, olay)
    
    # Clamp score between 0-10
    return max(0, min(10, skor))


def hesapla_toplu(olaylar: list) -> list:
    """Calculate scores for event list."""
    sonuclar = []
    
    for olay in olaylar:
        olay["skor"] = hesapla_skor(olay)
        olay["seviye"] = _seviye_belirle(olay["skor"])
        sonuclar.append(olay)
    
    return sonuclar


def _ayarla_ip(skor: float, olay: dict) -> float:
    """
    Adjust score based on source IP.
    External IPs increase risk.
    """
    kaynak_ip = olay.get("kaynak_ip")
    
    # Local/internal IP reduces risk
    if kaynak_ip in ["127.0.0.1", "::1", None]:
        return skor - 1.0
    
    # External IP increases risk
    if kaynak_ip and not _is_private_ip(kaynak_ip):
        return skor + 1.5
    
    return skor


def _ayarla_kullanici(skor: float, olay: dict) -> float:
    """
    Adjust score based on username.
    SYSTEM/LOCAL SERVICE reduce risk.
    """
    kullanici = olay.get("kullanici", "").upper()
    
    # System accounts are usually harmless
    if kullanici in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
        return skor - 0.5
    
    return skor


def _seviye_belirle(skor: float) -> str:
    """
    Determine severity level from score.
    
    Args:
        skor: Risk score 0-10
        
    Returns:
        str: Severity level
    """
    if skor >= 9.0:
        return "KRİTİK"
    elif skor >= 7.0:
        return "YÜKSEK"
    elif skor >= 4.0:
        return "ORTA"
    else:
        return "DÜŞÜK"


def _is_private_ip(ip: str) -> bool:
    """
    Check if IP is private/internal.
    
    Private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8 (loopback)
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        
        octets = [int(p) for p in parts]
        
        # 10.x.x.x
        if octets[0] == 10:
            return True
        
        # 172.16.x.x - 172.31.x.x
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        
        # 192.168.x.x
        if octets[0] == 192 and octets[1] == 168:
            return True
        
        # 127.x.x.x (loopback)
        if octets[0] == 127:
            return True
        
        return False
    except Exception:
        return False