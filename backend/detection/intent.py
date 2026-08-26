"""Deterministic natural-language intent parsing — zero AI, fully explainable."""

import re

SEVERITY_WORDS = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high risk": "HIGH", "high-risk": "HIGH", "high": "HIGH",
    "medium": "MEDIUM", "medium-risk": "MEDIUM",
    "low": "LOW",
}

THREAT_WORDS = {
    "brute force": "Brute Force", "bruteforce": "Brute Force",
    "password guessing": "Brute Force",
    "account compromise": "Account Compromise",
    "compromise": "Account Compromise",
    "port scan": "Port Scanning", "portscan": "Port Scanning", "scanning": "Port Scanning",
    "reconnaissance": "Reconnaissance", "recon": "Reconnaissance",
    "sql injection": "Web Attack", "sqli": "Web Attack", "sql": "Web Attack",
    "path traversal": "Web Attack", "traversal": "Web Attack",
    "xss": "Web Attack",
    "web attack": "Web Attack",
    "malware": "Malware",
    "powershell": "Command Execution",
    "privilege escalation": "Privilege Escalation", "privesc": "Privilege Escalation",
    "persistence": "Persistence",
}

TIME_PATTERNS = [
    (r"last\s+(\d+)\s*hours?", "hours"),
    (r"last\s+hour", "hour"),
    (r"last\s+(\d+)\s*minutes?", "minutes"),
    (r"last\s+minute", "minute"),
    (r"last\s+(\d+)\s*days?", "days"),
    (r"today", "today"),
]

AUTH_WORDS = ("auth", "login", "logon", "ssh")
PII_WORDS = ("pii", "email", "phone", "password", "token", "session")
IOC_TYPE_WORDS = {
    "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6",
    "domain": "domain", "domains": "domain",
    "url": "url", "urls": "url", "link": "url",
    "hash": "md5", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
}


def parse_intent(text: str) -> dict:
    """Translate a natural-language question into structured event filters."""
    original = text or ""
    t = original.lower()
    chips: list[dict] = []
    filters: dict = {}

    # severity — longest match wins
    for word in sorted(SEVERITY_WORDS, key=len, reverse=True):
        if re.search(rf"\b{re.escape(word)}\b", t):
            sev = SEVERITY_WORDS[word]
            filters["severity"] = sev
            chips.append({"key": "severity", "value": sev})
            break

    # threat category
    for word in sorted(THREAT_WORDS, key=len, reverse=True):
        if word in t:
            filters["threat_like"] = THREAT_WORDS[word]
            chips.append({"key": "threat≈", "value": THREAT_WORDS[word]})
            break

    # authentication-ish event types
    if any(w in t for w in AUTH_WORDS):
            filters["auth_events"] = True
            chips.append({"key": "type~", "value": "authentication*"})

    # PII flag
    if any(w in t for w in PII_WORDS):
        filters["has_pii"] = True
        chips.append({"key": "pii", "value": "detected"})

    # IOC type filter
    for word, itype in IOC_TYPE_WORDS.items():
        if re.search(rf"\b{word}s?\b", t):
            filters["ioc_type"] = itype
            chips.append({"key": "ioc_type", "value": itype})
            break

    # time windows
    for pattern, kind in TIME_PATTERNS:
        m = re.search(pattern, t)
        if m:
            if kind == "hour":
                filters["since_minutes"] = 60
            elif kind == "minute":
                filters["since_minutes"] = 1
            elif kind == "today":
                filters["since_today"] = True
            elif kind == "hours":
                filters["since_minutes"] = int(m.group(1)) * 60
            elif kind == "minutes":
                filters["since_minutes"] = int(m.group(1))
            elif kind == "days":
                filters["since_minutes"] = int(m.group(1)) * 60 * 24
            chips.append({"key": "window",
                          "value": f"last {filters.get('since_minutes')}m"})
            break

    # bare IP / entity extraction
    ipm = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", original)
    if ipm:
        filters["q"] = ipm.group(0)
        chips.append({"key": "entity", "value": ipm.group(0)})

    if not filters:
        filters["fallback_text"] = True

    return {"chips": chips, "filters": filters}
