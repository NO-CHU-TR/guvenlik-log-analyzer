"""Terminal rapor üreticisi — with rich library"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime

console = Console()

RENK_HARITASI = {
    "KRİTİK": "bold red",
    "YÜKSEK": "red",
    "ORTA":   "yellow",
    "DÜŞÜK":  "green"
}

def rapor_yaz(olaylar: list):
    """Skorlu olay listesinden terminal raporu üretir."""

    # Başlık
    console.print(Panel(
        f"[bold cyan]GÜVENLİK LOG ANALİZİ[/]\n"
        f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M')} | "
        f"Toplam Olay: {len(olaylar)}",
        border_style="cyan"
    ))

    # Özet sayaçlar
    sayac = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
    for o in olaylar:
        seviye = o.get("seviye", "DÜŞÜK")
        sayac[seviye] = sayac.get(seviye, 0) + 1

    console.print("\n[bold]Özet:[/]")
    for seviye, adet in sayac.items():
        renk = RENK_HARITASI[seviye]
        console.print(f"  [{renk}]{seviye:<10}[/]: {adet} olay")

    # Detay tablosu
    tablo = Table(
        title="\nDetaylı Olay Listesi",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )

    tablo.add_column("Seviye", width=10)
    tablo.add_column("Skor", width=6)
    tablo.add_column("Olay", width=30)
    tablo.add_column("Kullanıcı", width=15)
    tablo.add_column("Kaynak IP", width=15)
    tablo.add_column("Zaman", width=20)

    for olay in sorted(olaylar, key=lambda x: x.get("skor", 0), reverse=True)[:20]:
        seviye = olay.get("seviye", "DÜŞÜK")
        renk = RENK_HARITASI.get(seviye, "white")
        tablo.add_row(
            f"[{renk}]{seviye}[/]",
            f"[{renk}]{olay.get('skor', 0)}[/]",
            olay.get("aciklama", "")[:29],
            olay.get("kullanici") or "-",
            olay.get("kaynak_ip") or "-",
            olay.get("zaman", "")[:19]
        )

    console.print(tablo)