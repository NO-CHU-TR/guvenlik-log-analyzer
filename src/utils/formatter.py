"""
Formatting Functions
Helper functions to print data nicely.
"""


def table_header(title):
    """Print table header."""
    print("=" * 60)
    print(f"   {title}")
    print("=" * 60)


def event_row(event, width=60):
    """Print event as a row."""
    severity = event.get("seviye", "?")  # Change "severity" to "seviye"
    score = event.get("skor", 0)
    description = event.get("aciklama", "")[:40]
    
    return f"[{severity:<8}] {score:<5} | {description}"

def summary_print(events):
    """Print summary of event list."""
    counter = {}
    for event in events:
        severity = event.get("seviye", "DÜŞÜK")
        counter[severity] = counter.get(severity, 0) + 1
    
    print("\nSUMMARY:")
    for severity in ["KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"]:
        if severity in counter:
            print(f"  {severity:<10}: {counter[severity]} events")