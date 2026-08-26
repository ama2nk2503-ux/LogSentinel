"""Redaction modes: REDACT | TYPE | MASK | HASH | KEEP — policy-driven."""

import hashlib

from privacy.pii_detector import detect_pii


def _mask(value: str) -> str:
    if "@" in value and " " not in value:            # email-style
        local, _, domain = value.partition("@")
        dl, _, dtail = domain.rpartition(".")
        masked_local = local[:2] + "****" if len(local) > 2 else "****"
        return f"{masked_local}@{dl[:1]}****.{dtail}" if dl else f"{masked_local}@****"
    if len(value) <= 6:
        return "****"
    return value[:2] + "****" + value[-2:]


def _hash_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def redact_value(value: str, category: str, action: str) -> str:
    action = (action or "KEEP").upper()
    cat = category.upper()
    if action == "REDACT":
        return f"[{cat}_REDACTED]"
    if action == "TYPE":
        return f"[{cat}]"
    if action == "MASK":
        return _mask(value)
    if action == "HASH":
        return f"[{cat}:{_hash_id(value)}]"
    return value  # KEEP


def apply_policy(text: str, policy: dict[str, str]) -> tuple[str, list[str]]:
    """Replace every detected PII occurrence per policy. Returns (text, cats)."""
    if not text:
        return text, []
    hits = detect_pii(text)
    categories = sorted({h["type"] for h in hits})
    # longest-first so overlapping values replace atomically
    for hit in sorted(hits, key=lambda h: len(h["value"]), reverse=True):
        action = policy.get(hit["type"], policy.get("DEFAULT", "REDACT"))
        replacement = redact_value(hit["value"], hit["type"], action)
        if replacement != hit["value"]:
            text = text.replace(hit["value"], replacement)
    return text, categories


def sanitize_event(d: dict, policy: dict[str, str]) -> dict:
    """Output-gate: apply the privacy policy to free-text fields of a payload."""
    for field in ("message", "raw_line"):
        if isinstance(d.get(field), str):
            d[field], cats = apply_policy(d[field], policy)
            existing = set(d.get("pii_detected") or [])
            d["pii_detected"] = sorted(existing | set(cats))
    for t in d.get("timeline", []) or []:
        if isinstance(t, dict) and isinstance(t.get("excerpt"), str):
            t["excerpt"], _ = apply_policy(t["excerpt"], policy)
    for e in d.get("evidence", []) or []:
        if isinstance(e, dict) and isinstance(e.get("excerpt"), str):
            e["excerpt"], _ = apply_policy(e["excerpt"], policy)
    return d
