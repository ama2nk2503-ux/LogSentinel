"""Classifier: map detections/incidents to BENIGN / SUSPICIOUS / MALICIOUS.

Detected patterns are labeled honestly: single low-signal rules are
SUSPICIOUS; multi-factor or critical-severity chains are MALICIOUS.
"""

CRITICAL_CATEGORIES = {"command execution", "malware"}
MALICIOUS_SEVERITIES = {"CRITICAL"}


def classify_detection(severity: str, category: str, score: int) -> str:
    if severity.upper() in MALICIOUS_SEVERITIES or category.lower() in CRITICAL_CATEGORIES:
        return "MALICIOUS"
    if score >= 51 or severity.upper() == "HIGH":
        return "MALICIOUS"
    if score >= 21 or severity.upper() == "MEDIUM":
        return "SUSPICIOUS"
    return "BENIGN"


def classify_incident(score: int, categories: list[str], success_followup: bool) -> str:
    cats = {c.lower() for c in categories}
    if success_followup and ("brute force" in cats or "credential attack" in cats):
        return "MALICIOUS"
    if score >= 81 or (cats & CRITICAL_CATEGORIES):
        return "MALICIOUS"
    if score >= 31:
        return "SUSPICIOUS"
    return "BENIGN"


# Master-prompt Sec 11 category taxonomy (used for normalization of rule categories)
TAXONOMY = [
    "Brute Force", "Credential Attack", "Reconnaissance", "Port Scanning",
    "Malware", "Phishing", "Web Attack", "Data Exfiltration",
    "Privilege Escalation", "Command Execution", "Persistence",
    "Lateral Movement", "Unknown",
]


def normalize_category(category: str) -> str:
    c = (category or "").strip().lower()
    for t in TAXONOMY:
        if t.lower() == c:
            return t
    aliases = {
        "port scanning": "Port Scanning",
        "web attack": "Web Attack",
        "privilege escalation": "Privilege Escalation",
        "command execution": "Command Execution",
    }
    return aliases.get(c, "Unknown")
