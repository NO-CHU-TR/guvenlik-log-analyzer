"""
Graph Report Generator
Creates visualizations for security events.
"""

import matplotlib.pyplot as plt
import matplotlib
from datetime import datetime

# Use non-GUI backend
matplotlib.use('Agg')

# Turkish font support
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']


def grafikleri_olustur(olaylar: list, cikti_klasoru: str = "."):
    """
    Creates multiple graphs from security events.
    
    Args:
        olaylar: List of scored events
        cikti_klasoru: Output directory
    """
    if not olaylar:
        print("⚠️ Grafik oluşturulamadı: veri yok")
        return
    
    # Count by severity
    sayac = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
    for olay in olaylar:
        seviye = olay.get("seviye", "DÜŞÜK")
        sayac[seviye] = sayac.get(seviye, 0) + 1
    
    # Create figures
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Güvenlik Log Analizi - Grafikler", fontsize=16, fontweight='bold')
    plt.subplots_adjust(top=0.93, hspace=0.3, wspace=0.3)
    
    # 1. Bar Chart (Çubuk Grafik) - üst sol
    seviyeler = list(sayac.keys())
    sayilar = list(sayac.values())
    renkler = ['#e74c3c', '#e67e22', '#f39c12', '#27ae60']
    
    axes[0, 0].bar(seviyeler, sayilar, color=renkler)
    axes[0, 0].set_title("Seviyeler (Çubuk Grafik)", fontweight='bold')
    axes[0, 0].set_ylabel("Olay Sayısı")
    axes[0, 0].grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for i, v in enumerate(sayilar):
        axes[0, 0].text(i, v + 0.1, str(v), ha='center', va='bottom', fontweight='bold')
    
    # 2. Pie Chart (Pasta Grafik) - üst sağ
    axes[0, 1].pie(
        sayilar, 
        colors=renkler,
        autopct='%1.1f%%',
        startangle=90
    )
    axes[0, 1].set_title("Dağılım (Pasta Grafik)", fontweight='bold')
    axes[0, 1].legend(seviyeler, loc="upper left", bbox_to_anchor=(0.85, 1))
    
    # 3. Top Events (En Riskli Olaylar) - alt sol
    top_olaylar = sorted(olaylar, key=lambda x: x.get("skor", 0), reverse=True)[:10]
    aciklamalar = [o.get("aciklama", "")[:20] for o in top_olaylar]
    skorlar = [o.get("skor", 0) for o in top_olaylar]
    
    axes[1, 0].barh(range(len(aciklamalar)), skorlar, color='#3498db')
    axes[1, 0].set_yticks(range(len(aciklamalar)))
    axes[1, 0].set_yticklabels(aciklamalar, fontsize=9)
    axes[1, 0].set_xlabel("Risk Skoru")
    axes[1, 0].set_title("En Riskli 10 Olay", fontweight='bold')
    axes[1, 0].grid(axis='x', alpha=0.3)
    
    # 4. Summary Stats (Özet İstatistikler) - alt sağ
    axes[1, 1].axis('off')
    
    toplam = len(olaylar)
    kritik_yuzde = (sayac.get("KRİTİK", 0) / toplam * 100) if toplam > 0 else 0
    yuksek_yuzde = (sayac.get("YÜKSEK", 0) / toplam * 100) if toplam > 0 else 0
    
    summary_text = f"""
    ÖZET İSTATİSTİKLER
    
    Toplam Olay: {toplam}
    
    KRİTİK: {sayac.get('KRİTİK', 0)} ({kritik_yuzde:.1f}%)
    YÜKSEK: {sayac.get('YÜKSEK', 0)} ({yuksek_yuzde:.1f}%)
    ORTA: {sayac.get('ORTA', 0)}
    DÜŞÜK: {sayac.get('DÜŞÜK', 0)}
    
    Ortalama Skor: {sum(o.get('skor', 0) for o in olaylar) / toplam:.2f}/10
    """
    
    axes[1, 1].text(0.5, 0.5, summary_text, 
                   ha='center', va='center',
                   fontsize=11,
                   family='monospace',
                   bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8))
    
    # Save figure
    dosya_adi = f"{cikti_klasoru}/grafikler.png"
    plt.tight_layout()
    plt.savefig(dosya_adi, dpi=100, bbox_inches='tight')
    print(f"✅ Grafikler '{dosya_adi}' dosyasına kaydedildi")
    
    return dosya_adi