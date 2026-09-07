"""
Windows Event Log Parser
Converts raw event dict to clean, consistent format.
"""

from datetime import datetime


# Event ID to message field indices mapping
# Which field index contains which information for each event type
FIELD_MAP = {
    4625: {   # Failed logon
        "kullanici": 5,
        "kaynak_ip": 19,
        "giris_turu": 10,
    },
    4624: {   # Successful logon
        "kullanici": 5,
        "kaynak_ip": 18,
        "giris_turu": 8,
    },
    4720: {   # New user created
        "kullanici": 0,
        "olusturan": 4,
        "kaynak_ip": None,
    },
    4698: {   # Scheduled task created
        "kullanici": 0,
        "gorev_adi": 4,
        "kaynak_ip": None,
    },
}


def parse_event(ham_olay: dict) -> dict:
    """
    Converts raw event dict to clean format.

    Args:
        ham_olay: Raw record from windows_log.topla()

    Returns:
        dict: Clean, consistent event record
    """
    event_id = ham_olay.get("event_id", 0)
    mesaj = ham_olay.get("mesaj", [])

    # Base fields (same for all events)
    temiz = {
        "event_id": event_id,
        "aciklama": ham_olay.get("aciklama", "Bilinmiyor"),
        "zaman": _parse_zaman(ham_olay.get("zaman", "")),
        "kaynak": ham_olay.get("kaynak", ""),
        "kullanici": None,
        "kaynak_ip": None,
        "ek_bilgi": {}
    }

    # Event-specific fields
    # Get field mapping for this event ID
    harita = FIELD_MAP.get(event_id, {})
    for alan, indeks in harita.items():
        if indeks is not None:
            temiz[alan] = _safe_get(mesaj, indeks)
        else:
            temiz[alan] = None

    # Cleanup - remove local/internal IPs
    if temiz.get("kaynak_ip") in ["-", "::1", "127.0.0.1", None]:
        temiz["kaynak_ip"] = None

    return temiz


def parse_toplu(ham_olaylar: list) -> list:
    """Parse event list in bulk."""
    sonuclar = []
    for olay in ham_olaylar:
        try:
            temiz = parse_event(olay)
            sonuclar.append(temiz)
        except Exception as e:
            print(f"  ⚠️ Parse error (Event {olay.get('event_id')}): {e}")
    return sonuclar


def _safe_get(liste: list, indeks: int) -> str | None:
    """Get list value safely without index error."""
    try:
        deger = liste[indeks]
        return deger.strip() if isinstance(deger, str) else str(deger)
    except (IndexError, TypeError):
        return None


def _parse_zaman(zaman_str: str) -> str:
    """Convert time string to ISO format."""
    try:
        # Windows format: "2024-01-15 03:42:18+00:00"
        dt = datetime.fromisoformat(zaman_str.replace(" ", "T"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return zaman_str  # Return original if parsing fails