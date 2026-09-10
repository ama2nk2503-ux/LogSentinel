"""Shared exporter utilities: event fetching and timestamp helpers."""

import json
from datetime import datetime, timezone

from core.storage import db
from privacy.policy_engine import load_policy
from privacy.redactor import apply_policy


def fetch_events(job_id: str) -> list[dict]:
    policy = dict(load_policy())
    with db() as conn:
        rows = conn.execute(
            "SELECT e.*, j.filename AS _job_name FROM events e"
            " JOIN jobs j ON j.id = e.job_id WHERE e.job_id = ? ORDER BY e.id",
            (job_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["iocs"] = json.loads(d.pop("iocs_json") or "[]")
        d.pop("pii_json", None)
        d["pii_detected"] = json.loads(d.get("pii_json", "[]")) if "pii_json" in d else []
        msg, cats = apply_policy(d.get("message") or "", policy)
        d["message"], d["pii_detected"] = msg, sorted(set(d.get("pii_detected") or []) | set(cats))
        out.append(d)
    return out


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
