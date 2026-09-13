"""Ask-the-Data endpoint: deterministic intent -> filtered processed events.

`query_events` is the shared evidence lookup (also used by the AI assistant)
so intent-driven event retrieval stays implementation-identical everywhere.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.storage import db
from detection.intent import parse_intent
from privacy.policy_engine import load_policy
from privacy.redactor import apply_policy

router = APIRouter()


class QueryBody(BaseModel):
    job_id: str
    text: str = Field(min_length=1, max_length=500)


def _job_exists(job_id: str) -> bool:
    with db() as conn:
        return conn.execute("SELECT id FROM jobs WHERE id=?",
                            (job_id,)).fetchone() is not None


def query_events(job_id: str, filters: dict, limit: int = 25) -> dict:
    """Resolve deterministic filters to redacted events for a job.

    Returns {'filters', 'fallback', 'total', 'events'} with message text
    passed through the privacy redaction policy before leaving the engine.
    """
    where, params = ["job_id = ?"], [job_id]

    if filters.get("severity"):
        # An event's own severity is often LOW; "high-risk" means *flagged by a
        # HIGH/CRITICAL rule* — so match through detection evidence.
        where.append(
            "(UPPER(severity) = ? OR EXISTS ("
            "  SELECT 1 FROM detections d, json_each(d.evidence_json) ev"
            "  WHERE d.job_id = events.job_id"
            "    AND UPPER(d.severity) = ?"
            "    AND json_extract(ev.value,'$.event_id') = events.event_id))")
        params.extend([filters["severity"], filters["severity"]])
    if filters.get("threat_like"):
        like = f"%{filters['threat_like']}%"
        where.append("(threat_type LIKE ? OR event_type LIKE ? OR username LIKE ?)")
        params.extend([like, like, like])
    if filters.get("auth_events"):
        where.append("event_type LIKE '%auth%'")
    if filters.get("has_pii"):
        where.append("pii_json != '[]'")
    if filters.get("ioc_type"):
        where.append(
            "EXISTS (SELECT 1 FROM json_each(events.iocs_json) j"
            " WHERE json_extract(j.value,'$.type') = ?)")
        params.append(filters["ioc_type"])
    if filters.get("q"):
        like = f"%{filters['q']}%"
        where.append("(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR username LIKE ?)")
        params.extend([like] * 4)
    if filters.get("since_minutes"):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=filters["since_minutes"])
                  ).isoformat().replace("+00:00", "Z")
        where.append("ts >= ?")
        params.append(cutoff)
    elif filters.get("since_today"):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00")
        where.append("ts >= ?")
        params.append(today)

    fallback = bool(filters.get("fallback_text"))
    if fallback:
        words = [w for w in filters.get("_text", "").split() if len(w) > 3][:3]
        if words:
            likes = " OR ".join(["message LIKE ?"] * len(words))
            where.append(f"({likes})")
            params.extend([f"%{w}%" for w in words])

    clause = " AND ".join(where)
    with db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM events WHERE {clause}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT event_id, ts, event_type, src_ip, dst_ip, username,"
            f" severity, threat_type, risk_score, message FROM events"
            f" WHERE {clause} ORDER BY ts DESC LIMIT {limit}",
            params).fetchall()

    policy = dict(load_policy())
    events = []
    for r in rows:
        d = dict(r)
        d["message"], _ = apply_policy(d.get("message") or "", policy)
        events.append(d)

    return {
        "filters": {k: v for k, v in filters.items() if not k.startswith("_")},
        "fallback": fallback,
        "total": total,
        "events": events,
    }


@router.post("/query")
def ask_the_data(body: QueryBody):
    if not _job_exists(body.job_id):
        raise HTTPException(404, "Job not found")
    parsed = parse_intent(body.text)
    filters = dict(parsed["filters"])
    filters["_text"] = body.text
    out = query_events(body.job_id, filters)

    return {
        "query": body.text,
        "chips": parsed["chips"],
        "note": ("no structured intent found — used fallback text match"
                 if out["fallback"] else None),
        "total": out["total"],
        "events": out["events"],
    }
