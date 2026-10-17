"""
Trend Analysis Reporter
Compares the two most recent scans stored in the database.
"""

from src.database.models import init_db, get_session, ScanResult


def trend_analizi(db_path: str = "guvenlik.db"):
    """Compare the last two scans and print the trend."""
    engine = init_db(db_path)
    session = get_session(engine)

    taramalar = session.query(ScanResult).order_by(ScanResult.scan_date).all()

    if len(taramalar) < 2:
        print("⚠️ Trend analizi için en az 2 tarama gerekli")
        session.close()
        return

    onceki = taramalar[-2]
    simdi = taramalar[-1]

    print("=" * 60)
    print("TREND ANALİZİ")
    print("=" * 60)

    print(f"\nÖnceki Tarama: {onceki.scan_date.strftime('%Y-%m-%d %H:%M')}")
    print(f"  Toplam: {onceki.total_events}")
    print(f"  KRİTİK: {onceki.kritik_count}")
    print(f"  YÜKSEK: {onceki.yuksek_count}")

    print(f"\nBu Tarama: {simdi.scan_date.strftime('%Y-%m-%d %H:%M')}")
    print(f"  Toplam: {simdi.total_events}")
    print(f"  KRİTİK: {simdi.kritik_count}")
    print(f"  YÜKSEK: {simdi.yuksek_count}")

    delta_kritik = simdi.kritik_count - onceki.kritik_count
    delta_yuksek = simdi.yuksek_count - onceki.yuksek_count
    delta_toplam = simdi.total_events - onceki.total_events

    print("\nDEĞİŞİM:")

    if delta_toplam < 0:
        toplam_yorum = "İyi"
    elif delta_toplam == 0:
        toplam_yorum = "Değişmedi"
    else:
        toplam_yorum = "Arttı"

    kritik_yorum = "İyi" if delta_kritik <= 0 else "UYARI!"
    yuksek_yorum = "İyi" if delta_yuksek <= 0 else "UYARI!"

    print(f"  Toplam: {delta_toplam:+d} ({toplam_yorum})")
    print(f"  KRİTİK: {delta_kritik:+d} ({kritik_yorum})")
    print(f"  YÜKSEK: {delta_yuksek:+d} ({yuksek_yorum})")

    if delta_kritik > 0 or delta_yuksek > 0:
        print("\n⚠️ TREND: Kötüleşiyor!")
    elif delta_toplam < 0:
        print("\n✅ TREND: İyileşiyor!")
    else:
        print("\n➡️ TREND: Stabil!")

    session.close()