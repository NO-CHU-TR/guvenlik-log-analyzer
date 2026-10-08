"""
HTML Report Generator
Creates professional HTML reports from security events.
"""

from jinja2 import Template
from datetime import datetime


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenlik Log Analizi Raporu</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        .header-info {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        
        .summary-box {
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        
        .kritik { background-color: #e74c3c; }
        .yuksek { background-color: #e67e22; }
        .orta { background-color: #f39c12; }
        .dusuk { background-color: #27ae60; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th {
            background-color: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }
        
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        tr:hover {
            background-color: #f0f0f0;
        }
        
        .seviye-kritik { color: #e74c3c; font-weight: bold; }
        .seviye-yuksek { color: #e67e22; font-weight: bold; }
        .seviye-orta { color: #f39c12; font-weight: bold; }
        .seviye-dusuk { color: #27ae60; font-weight: bold; }
        
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Güvenlik Log Analizi Raporu</h1>
        
        <div class="header-info">
            <p><strong>Rapor Tarihi:</strong> {{ tarih }}</p>
            <p><strong>Toplam Olay Sayısı:</strong> {{ toplam_olay }}</p>
        </div>
        
        <h2>Özet</h2>
        <div class="summary">
            <div class="summary-box kritik">
                🔴 KRİTİK<br>
                {{ ozet['KRİTİK'] }}
            </div>
            <div class="summary-box yuksek">
                🟠 YÜKSEK<br>
                {{ ozet['YÜKSEK'] }}
            </div>
            <div class="summary-box orta">
                🟡 ORTA<br>
                {{ ozet['ORTA'] }}
            </div>
            <div class="summary-box dusuk">
                🟢 DÜŞÜK<br>
                {{ ozet['DÜŞÜK'] }}
            </div>
        </div>
        
        <h2>Detaylı Olay Listesi</h2>
        <table>
            <thead>
                <tr>
                    <th>Seviye</th>
                    <th>Skor</th>
                    <th>Olay Açıklaması</th>
                    <th>Kullanıcı</th>
                    <th>Kaynak IP</th>
                    <th>Zaman</th>
                </tr>
            </thead>
            <tbody>
                {% for olay in olaylar[:50] %}
                <tr>
                    <td><span class="seviye-{{ olay['seviye']|lower }}">{{ olay['seviye'] }}</span></td>
                    <td>{{ "%.1f"|format(olay['skor']) }}/10</td>
                    <td>{{ olay['aciklama'] }}</td>
                    <td>{{ olay.get('kullanici', '-') }}</td>
                    <td>{{ olay.get('kaynak_ip', '-') }}</td>
                    <td>{{ olay['zaman'] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Bu rapor otomatik olarak güvenlik log analizi sistemi tarafından oluşturulmuştur.</p>
        </div>
    </div>
</body>
</html>
"""


def rapor_olustur(olaylar: list, cikti_dosyasi: str = "rapor.html"):
    """
    Creates HTML report from scored events.
    
    Args:
        olaylar: List of scored events
        cikti_dosyasi: Output filename
    """
    # Count by severity
    ozet = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
    for olay in olaylar:
        seviye = olay.get("seviye", "DÜŞÜK")
        ozet[seviye] = ozet.get(seviye, 0) + 1
    
    # Prepare data for template
    template_data = {
        "tarih": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "toplam_olay": len(olaylar),
        "ozet": ozet,
        "olaylar": sorted(olaylar, key=lambda x: x.get("skor", 0), reverse=True)
    }
    
    # Render template
    template = Template(HTML_TEMPLATE)
    html_content = template.render(**template_data)
    
    # Write to file
    with open(cikti_dosyasi, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"✅ HTML raporu '{cikti_dosyasi}' dosyasına kaydedildi")
    return cikti_dosyasi