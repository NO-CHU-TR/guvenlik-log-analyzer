"""
AI Interpreter
Sends a security event to a local Ollama model and asks for a short analysis.
"""

import json
import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"


def _prompt_olustur(olay: dict) -> str:
    """Build a strict prompt that asks for JSON only."""
    return f"""Sen bir siber güvenlik analistisin.
Aşağıdaki Windows güvenlik olayını analiz et.
SADECE JSON döndür, başka hiçbir metin yazma.

Olay: {olay.get('aciklama')}
Event ID: {olay.get('event_id')}
Skor: {olay.get('skor')}
Seviye: {olay.get('seviye')}
Kullanıcı: {olay.get('kullanici') or 'bilinmiyor'}
Kaynak IP: {olay.get('kaynak_ip') or 'bilinmiyor'}

JSON formatı:
{{"tehdit_turu": "...", "ozet": "...", "aksiyonlar": ["...", "..."]}}
"""


def _json_ayikla(metin: str) -> dict | None:
    """Pull the JSON object out of the model's reply, if there is one."""
    bas = metin.find("{")
    son = metin.rfind("}")
    if bas == -1 or son == -1 or son < bas:
        return None
    try:
        return json.loads(metin[bas:son + 1])
    except json.JSONDecodeError:
        return None


def yorumla(olay: dict) -> dict:
    """
    Ask the local model to interpret one event.
    Never raises: on any failure returns a fallback dict.
    """
    yedek = {
        "tehdit_turu": "Bilinmiyor",
        "ozet": "AI yorumu alınamadı.",
        "aksiyonlar": [],
    }
    try:
        cevap = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": _prompt_olustur(olay),
                "stream": False,
                "format": "json",
            },
            timeout=120,
        )
        cevap.raise_for_status()
        sonuc = _json_ayikla(cevap.json().get("response", ""))
        return sonuc or yedek
    except requests.RequestException:
        return yedek