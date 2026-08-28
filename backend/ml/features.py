"""Deterministic feature extraction for the in-loop ML anomaly scorer.

Every event becomes a fixed-length numeric vector interpreted by an
IsolationForest. Features are chosen to be format-agnostic (ssh / firewall /
apache / windows all normalize to the same columns) and deterministic:
ordinal encodings use explicit maps or a per-job LabelEncoder, never
Python's randomized str hash().
"""

import json
from datetime import datetime

SEVERITY_ORD = {"": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
GEO_KIND_ORD = {"": 0, "unknown": 0, "reserved": 1, "private": 2, "public": 3}

FEATURE_NAMES = [
    "hour", "weekday", "msg_len", "src_port", "dst_port", "ioc_count",
    "pii_count", "risk_score", "sev_ord", "suspicious", "intel_match",
    "geo_src_kind", "geo_dst_kind", "event_type_ord", "status_ord",
    "protocol_ord",
]

CAT_COLUMNS = ["event_type", "status", "protocol"]


def _ts_parts(ts: str | None) -> tuple[int, int]:
    if not ts:
        return -1, -1
    clean = str(ts).replace("Z", "+00:00")
    if len(clean) == 19:
        clean = clean.replace(" ", "T")
    try:
        dt = datetime.fromisoformat(clean)
    except ValueError:
        return -1, -1
    return dt.hour, dt.weekday()


def _ioc_count(iocs_json: str) -> int:
    try:
        return len(json.loads(iocs_json or "[]"))
    except (ValueError, TypeError):
        return 0


def _pii_count(pii_json: str) -> int:
    try:
        return len(json.loads(pii_json or "[]"))
    except (ValueError, TypeError):
        return 0


def _extras(row: dict) -> dict:
    try:
        ex = json.loads(row.get("extras_json") or "{}")
    except (ValueError, TypeError):
        ex = {}
    return ex if isinstance(ex, dict) else {}


def extract_features(row: dict, cat_map: dict[str, dict[str, int]]) -> list[float]:
    """Vectorize one event row (dict of events-table columns).

    cat_map is the fitted LabelEncoder mapping per categorical column
    ({column: {value: index}}); values the encoder never saw map to the
    count of seen values (a novel class), keeping predictions stable.
    """
    hour, weekday = _ts_parts(row.get("ts"))
    extras = _extras(row)
    geo_src = extras.get("geo_src") or {}
    geo_dst = extras.get("geo_dst") or {}
    sev = str(row.get("severity") or "").upper()
    ev_type = str(row.get("event_type") or "")

    def cat(col: str, value: str) -> float:
        m = cat_map.get(col) or {}
        return m.get(value, len(m))

    return [
        float(hour), float(weekday),
        float(len(str(row.get("message") or ""))),
        float(row.get("src_port") or -1),
        float(row.get("dst_port") or -1),
        float(_ioc_count(row.get("iocs_json") or "")),
        float(_pii_count(row.get("pii_json") or "")),
        float(row.get("risk_score") or 0),
        float(SEVERITY_ORD.get(sev, 0)),
        float(1 if extras.get("suspicious") else 0),
        float(1 if extras.get("intel_match") else 0),
        float(GEO_KIND_ORD.get(str(geo_src.get("kind") or ""), 0)),
        float(GEO_KIND_ORD.get(str(geo_dst.get("kind") or ""), 0)),
        cat("event_type", ev_type),
        cat("status", str(row.get("status") or "")),
        cat("protocol", str(row.get("protocol") or "")),
    ]