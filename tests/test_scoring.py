"""
Tests for the CVSS-style scorer.
Pure logic only: no Windows APIs, so these run on GitHub's Linux servers too.
"""

from src.scoring.cvss_scorer import hesapla_skor, _seviye_belirle


def test_seviye_kritik():
    assert _seviye_belirle(9.5) == "KRİTİK"


def test_seviye_dusuk():
    assert _seviye_belirle(2.0) == "DÜŞÜK"


def test_skor_0_ile_10_arasinda():
    olay = {"event_id": 4625, "kaynak_ip": "8.8.8.8", "kullanici": "admin"}
    skor = hesapla_skor(olay)
    assert 0 <= skor <= 10


def test_bilinmeyen_event_varsayilan_skor():
    # Unknown event -> 5.0 base, then -1.0 for local/None IP = 4.0
    olay = {"event_id": 99999, "kaynak_ip": None, "kullanici": "test"}
    skor = hesapla_skor(olay)
    assert skor == 4.0


def test_sistem_kullanicisi_riski_dusurur():
    sistem = {"event_id": 4624, "kaynak_ip": None, "kullanici": "SYSTEM"}
    normal = {"event_id": 4624, "kaynak_ip": None, "kullanici": "oyku"}
    assert hesapla_skor(sistem) < hesapla_skor(normal)