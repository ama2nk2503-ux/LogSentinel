"""Per-feature anomaly explanations (M5 Item 7).

The anomaly score is one number; this module explains *why*. For any event it
ranks the top features by z-score distance against the job's per-feature
mean/std computed during training (stored in ml_models.params_json + the warm
model cache — no new model, no retraining). Phrases render original event
values so the reason is human-readable, e.g.
    message length 812 vs job mean 96
    dst_port unusual: 6666 vs job typical 80
"""

import json

from ml.features import FEATURE_NAMES, CAT_COLUMNS, extract_features

_TOP_N = 3

# Display labels for human-readable reasons.
_LABELS = {
    "hour": "hour",
    "weekday": "weekday",
    "msg_len": "message length",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "ioc_count": "IOC count",
    "pii_count": "PII count",
    "risk_score": "risk score",
    "sev_ord": "severity ordinal",
    "suspicious": "suspicious flag",
    "intel_match": "intel-match flag",
    "geo_src_kind": "geo src kind",
    "geo_dst_kind": "geo dst kind",
    "event_type_ord": "event_type",
    "status_ord": "status",
    "protocol_ord": "protocol",
}

# Features whose phrase shows the job's typical (modal) raw value.
_MODE_FEATURES = {"src_port", "dst_port"}
# Categorical features rendered with the RAW value, not the encoded ordinal.
_CAT_DISPLAY = {f"event_type_ord": "event_type", "status_ord": "status",
                "protocol_ord": "protocol"}


def _raw_value(name: str, row: dict) -> object:
    """Recover the event's original value for a feature name (for display)."""
    if name == "hour":
        return _raw_ts_part(row, 0)
    if name == "weekday":
        return _raw_ts_part(row, 1)
    if name == "msg_len":
        return len(str(row.get("message") or ""))
    if name == "src_port":
        return int(row.get("src_port") or -1)
    if name == "dst_port":
        return int(row.get("dst_port") or -1)
    if name == "ioc_count":
        return _len_json(row.get("iocs_json"))
    if name == "pii_count":
        return _len_json(row.get("pii_json"))
    if name == "risk_score":
        return int(row.get("risk_score") or 0)
    if name == "sev_ord":
        from ml.features import SEVERITY_ORD
        return SEVERITY_ORD.get(str(row.get("severity") or "").upper(), 0)
    if name == "suspicious":
        from ml.features import _extras
        return int(1 if _extras(row).get("suspicious") else 0)
    if name == "intel_match":
        from ml.features import _extras
        return int(1 if _extras(row).get("intel_match") else 0)
    if name == "geo_src_kind" or name == "geo_dst_kind":
        from ml.features import GEO_KIND_ORD, _extras
        key = "geo_src" if name == "geo_src_kind" else "geo_dst"
        return GEO_KIND_ORD.get(str((_extras(row).get(key) or {}).get("kind") or ""), 0)
    if name in _CAT_DISPLAY:
        return str(row.get(_CAT_DISPLAY[name]) or "")
    return 0


def _raw_ts_part(row: dict, part: int) -> int:
    from ml.features import _ts_parts
    h, w = _ts_parts(row.get("ts"))
    return h if part == 0 else w


def _len_json(raw) -> int:
    try:
        return len(json.loads(raw or "[]"))
    except (ValueError, TypeError):
        return 0


def _phrase(name: str, z: float, value, stats: dict, typical: dict) -> str:
    col = stats.get(name) or {}
    mean = col.get("mean")
    if name in _MODE_FEATURES:
        mode = typical.get(name)
        if mode is not None:
            return f"{_LABELS[name]} unusual: {value} vs job typical {mode}"
        return f"{_LABELS[name]} unusual: {value} (z={z:.2f})"
    if name == "msg_len" and mean is not None:
        return f"message length {value} vs job mean {mean:.0f}"
    if name in _CAT_DISPLAY:
        return f"{_LABELS[name]} '{value}' unusual (z={z:.2f})"
    if mean is not None:
        return f"{_LABELS[name]} {value} vs job mean {mean:.1f}"
    return f"{_LABELS[name]} unusual: {value} (z={z:.2f})"


def _feature_stats(job_id: str) -> tuple[dict, dict]:
    """Per-feature mean/std + typical values recorded during training."""
    from ml import model as ml_model
    with ml_model._lock:
        cached = ml_model._cache.get(job_id)
    if cached and cached.get("feature_stats"):
        return cached["feature_stats"], cached.get("feature_typical") or {}
    meta = ml_model._meta(job_id) or {}
    return meta.get("feature_stats") or {}, meta.get("feature_typical") or {}


def top_features(job_id: str, row: dict) -> list[str]:
    """Top contributing features for one event, as plain-text reasons.

    Deterministic: ranking is by |z-score| (std > 0) with feature order and
    (z, value) as tie-breaks. Returns [] when the job has no trained stats.
    """
    from ml import model as ml_model
    stats, typical = _feature_stats(job_id)
    if not stats:
        return []
    with ml_model._lock:
        cached = ml_model._cache.get(job_id)
    cat_map = (cached or {}).get("cat_map") or {}
    if not cat_map:
        meta = ml_model._meta(job_id) or {}
        cat_map = meta.get("cat_map") or {}
    x = extract_features(row, cat_map)
    ranked = []
    for idx, name in enumerate(FEATURE_NAMES):
        col = stats.get(name)
        if not col or not col.get("std"):
            continue
        z = (float(x[idx]) - col["mean"]) / col["std"]
        value = _raw_value(name, row)
        ranked.append((abs(z), z, idx, name, value))
    ranked.sort(key=lambda t: (-t[0], t[2], -t[1]))
    out = []
    for _, z, _, name, value in ranked[:_TOP_N]:
        out.append(_phrase(name, z, value, stats, typical))
    return out


def summary(job_id: str, row: dict) -> str:
    """One-line detail for embedding after the '+N ML anomaly signal' reason."""
    details = top_features(job_id, row)
    if not details:
        return ""
    return " | ML detail: " + "; ".join(details)