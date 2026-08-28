"""Threat-intelligence reference feed + reputation lookups.

The bundled feed (rules/intel_reference.yaml) provides deterministic
reputation for known-bad values; the aggregation is enriched with every
job's extracted indicators (indicators table), which act as sightings.
All lookups are offline and reproducible.
"""

import json

import yaml

from core.config import settings
from core.storage import db

INTEL_REFERENCE_FILE = "intel_reference.yaml"

_REF: dict[str, dict] | None = None


def _load_feed() -> list[dict]:
    path = settings.rules_dir / INTEL_REFERENCE_FILE
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for raw in data.get("indicators", []):
        if isinstance(raw, dict) and raw.get("value"):
            out.append({
                "value": str(raw["value"]).strip().lower(),
                "type": str(raw.get("type", "ipv4")).strip(),
                "threat_type": str(raw.get("threat_type", "")).strip(),
                "severity": str(raw.get("severity", "LOW")).strip().upper(),
                "confidence": min(1.0, max(0.0, float(raw.get("confidence", 0.0)))),
                "source": str(raw.get("source", "")).strip(),
                "tags": list(raw.get("tags", [])),
            })
    return out


def load_reference() -> dict[str, dict]:
    """value (lowercased) -> feed entry. Cached per process."""
    global _REF
    if _REF is None:
        _REF = {e["value"]: e for e in _load_feed()}
    return _REF


def seed_intel_reference() -> int:
    with db() as conn:
        if conn.execute("SELECT COUNT(*) c FROM intel_reference").fetchone()["c"]:
            return 0
        for e in _load_feed():
            conn.execute(
                "INSERT OR IGNORE INTO intel_reference"
                " (value, type, threat_type, severity, confidence, source, tags_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (e["value"], e["type"], e["threat_type"], e["severity"],
                 e["confidence"], e["source"], json.dumps(e["tags"])))
    return len(_load_feed())


def reload_intel_reference() -> int:
    global _REF
    _REF = {e["value"]: e for e in _load_feed()}
    with db() as conn:
        conn.execute("DELETE FROM intel_reference")
        for e in _load_feed():
            conn.execute(
                "INSERT INTO intel_reference (value, type, threat_type, severity,"
                " confidence, source, tags_json) VALUES (?,?,?,?,?,?,?)",
                (e["value"], e["type"], e["threat_type"], e["severity"],
                 e["confidence"], e["source"], json.dumps(e["tags"])))
    return len(_load_feed())


def list_reference() -> list[dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM intel_reference ORDER BY confidence DESC, value").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d.pop("tags_json") or "[]")
        out.append(d)
    return out


def _verdict(severity: str, confidence: float) -> str:
    if confidence >= 0.9 or severity in ("CRITICAL", "HIGH"):
        return "malicious"
    if confidence >= 0.7 or severity == "MEDIUM":
        return "suspicious"
    return "informational"


def lookup(value: str) -> dict | None:
    """Reference-only match (fast path used by pipeline enrichment)."""
    entry = load_reference().get((value or "").strip().lower())
    if not entry:
        return None
    return dict(entry)


def reputation(value: str) -> dict:
    """Full reputation assessment: reference feed + historical sightings.

    Sightings come from the persistent indicators watchlist (all jobs),
    which lets the analyst see where this value was last observed.
    """
    key = (value or "").strip().lower()
    ref = load_reference().get(key)
    sightings = []
    with db() as conn:
        rows = conn.execute(
            "SELECT value, type, threat_type, severity, confidence,"
            " first_seen, last_seen, related_events"
            " FROM indicators WHERE lower(value) = ? ORDER BY last_seen DESC",
            (key,)).fetchall()
        sightings = [dict(r) for r in rows]

    if not ref and not sightings:
        return {"value": value, "type": "unknown", "verdict": "unknown",
                "threat_type": "", "severity": "LOW", "confidence": 0.0,
                "source": "", "tags": [], "sightings": [],
                "first_seen": None, "last_seen": None, "related_events": 0}

    severity = (ref or sightings[0]).get("severity", "LOW")
    confidence = float((ref or sightings[0]).get("confidence", 0.0))
    return {
        "value": value,
        "type": (ref or sightings[0]).get("type", "unknown"),
        "verdict": _verdict(severity, confidence),
        "threat_type": (ref or sightings[0]).get("threat_type", ""),
        "severity": severity,
        "confidence": confidence,
        "source": (ref or {}).get("source", ""),
        "tags": (ref or {}).get("tags", []),
        "sightings": sightings,
        "first_seen": sightings[0]["first_seen"] if sightings else None,
        "last_seen": sightings[0]["last_seen"] if sightings else None,
        "related_events": sum(int(x["related_events"] or 0) for x in sightings),
    }


def enrich_event(src_ip: str | None, dst_ip: str | None, iocs: list[dict]) -> dict | None:
    """Best single reference match for an event: src -> dst -> IOC value."""
    ref = load_reference()
    for val in (src_ip, dst_ip):
        if val and (val.strip().lower()) in ref:
            return ref[val.strip().lower()]
    for ioc in iocs or []:
        key = str(ioc.get("value", "")).strip().lower()
        if key and key in ref:
            return ref[key]
    return None