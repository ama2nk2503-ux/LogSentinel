"""PII/sensitive-data detection. Not every IP is PII — categories are explicit."""

import re

PII_CATEGORIES = [
    "EMAIL", "PHONE", "PASSWORD", "API_KEY", "TOKEN",
    "SESSION_ID", "ACCOUNT_NUMBER", "EMPLOYEE_ID", "NAME",
]

EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RX = re.compile(
    r"(?<![\w.])(?:"
    r"\+\d{1,3}[-.\s]?\d{3,5}[-.\s]?\d{3,5}(?:[-.\s]?\d{2,4})?"   # international
    r"|\(\d{3}\)\s?\d{3}[-.\s]\d{4}"                              # (xxx) xxx-xxxx
    r"|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"                           # national blocks
    r"|\b\d{5}[-.\s]\d{4,5}\b"                                    # 5+4 / 5+5 local
    r")(?![\w.\-])"
)
PASSWORD_RX = re.compile(
    r"\b(?:password|passwd|pwd)\b[\"':=\s]+([^\s\"',;]{4,})", re.I
)
API_KEY_RX = re.compile(
    r"(?:\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key)\b[\"':=\s]+[^\s\"',;]{8,})",
    re.I,
)
TOKEN_RX = re.compile(
    r"\b(?:token|bearer|authorization)\b[\"':=\s]*[:=]?\s*[\"']?([A-Za-z0-9._\-]{16,})",
    re.I,
)
SESSION_RX = re.compile(
    r"\bsession[_-]?id\b[\"':=\s]*[=:]\s*[\"']?([A-Za-z0-9\-]{8,})", re.I
)
ACCOUNT_RX = re.compile(
    r"\baccount(?:[_ -]?number|[#\s])*[:=]?\s*([0-9]{6,17})\b|\b(IBAN\s+[A-Z]{2}[0-9A-Z]{13,32})", re.I
)
EMPLOYEE_RX = re.compile(r"\bEMP-?[0-9]{4,8}\b", re.I)
# Conservative person-name heuristic: "user Jane Doe ..." / "... for Jane Doe "
NAME_RX = re.compile(
    r"(?i:user|users|for)\s+([A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20})(?![a-z])"
)


def _add(found: list[dict], cat: str, value: str, conf: float):
    value = value.strip()
    if value and len(value) >= 3:
        found.append({"type": cat, "value": value, "confidence": conf})


def detect_pii(text: str) -> list[dict]:
    """Return unique PII hits with category + matched value."""
    if not text:
        return []
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(cat, val, conf):
        val = (val or "").strip()
        key = (cat, val)
        if len(val) >= 3 and key not in seen:
            seen.add(key)
            _add(found, cat, val, conf)

    for m in EMAIL_RX.finditer(text):
        add("EMAIL", m.group(0), 0.99)
    for m in PHONE_RX.finditer(text):
        add("PHONE", m.group(0), 0.85)
    for m in PASSWORD_RX.finditer(text):
        add("PASSWORD", m.group(1), 0.97)
    for m in API_KEY_RX.finditer(text):
        add("API_KEY", m.group(0), 0.95)
    for m in TOKEN_RX.finditer(text):
        add("TOKEN", m.group(1), 0.93)
    for m in SESSION_RX.finditer(text):
        add("SESSION_ID", m.group(1), 0.93)
    for m in ACCOUNT_RX.finditer(text):
        add("ACCOUNT_NUMBER", m.group(1) or m.group(2), 0.9)
    for m in EMPLOYEE_RX.finditer(text):
        add("EMPLOYEE_ID", m.group(0), 0.95)
    for m in NAME_RX.finditer(text):
        add("NAME", m.group(1), 0.7)
    return found
