"""
PHASE 11 — Checkov Integration
Reads Checkov JSON output and saves failed checks to the database.
"""

import json
import os
from datetime import datetime

from src.database.models import init_db, get_session, SecurityEvent

CHECKOV_JSON = "results_json.json"

# Risk score per Checkov rule (teaching mapping)
CHECK_SCORES = {
    "CKV_DOCKER_1": 7.5,   # Port 22 exposed
    "CKV_DOCKER_8": 7.5,   # Last user is root
    "CKV_DOCKER_4": 5.5,   # ADD instead of COPY
    "CKV_DOCKER_2": 3.0,   # No HEALTHCHECK
}
DEFAULT_SCORE = 5.0


def _seviye(skor: float) -> str:
    if skor >= 9.0:
        return "KRİTİK"
    elif skor >= 7.0:
        return "YÜKSEK"
    elif skor >= 4.0:
        return "ORTA"
    return "DÜŞÜK"


def load_failed_checks(path: str) -> list:
    # utf-8-sig handles files with or without a BOM
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)

    # Single framework gives a dict, multiple frameworks give a list
    reports = data if isinstance(data, list) else [data]

    findings = []
    for report in reports:
        findings.extend(report.get("results", {}).get("failed_checks", []))
    return findings


def to_event(check: dict) -> SecurityEvent:
    check_id = check.get("check_id", "UNKNOWN")
    score = CHECK_SCORES.get(check_id, DEFAULT_SCORE)

    return SecurityEvent(
        event_id=9000,  # Our own ID for IaC findings
        aciklama=f"{check_id}: {check.get('check_name', '')}"[:255],
        skor=score,
        seviye=_seviye(score),
        kullanici=None,
        kaynak_ip=None,
        zaman=datetime.now(),
    )


def main():
    if not os.path.exists(CHECKOV_JSON):
        print(f"⚠️ '{CHECKOV_JSON}' bulunamadı. Önce Checkov'u JSON çıktısıyla çalıştır.")
        return

    findings = load_failed_checks(CHECKOV_JSON)
    print(f"Checkov failed checks: {len(findings)}")

    if not findings:
        print("ℹ️ Kaydedilecek bulgu yok.")
        return

    engine = init_db("guvenlik.db")
    session = get_session(engine)
    try:
        for check in findings:
            session.add(to_event(check))
        session.commit()
        print(f"✅ {len(findings)} bulgu veritabanına kaydedildi")
    finally:
        session.close()


if __name__ == "__main__":
    main()