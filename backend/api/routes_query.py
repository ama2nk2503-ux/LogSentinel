"""Ask-the-Data endpoint: deterministic intent -> filtered processed events."""

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


@router.post("/query")
def ask_the_data(body: QueryBody):
    parsed = parse_intent(body.text)
    f = parsed["filters"]

    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id=?",
                        (body.job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")

    where, params = ["job_id = ?"], [body.job_id]

    if f.get("severity"):
        # An event's own severity is often LOW; "high-risk" means *flagged by a
        # HIGH/CRITICAL rule* — so match through detection evidence.
        where.append(
            "(UPPER(severity) = ? OR EXISTS ("
            "  SELECT 1 FROM detections d, json_each(d.evidence_json) ev"
            "  WHERE d.job_id = events.job_id"
            "    AND UPPER(d.severity) = ?"
            "    AND json_extract(ev.value,'$.event_id') = events.event_id))")
        params.extend([f["severity"], f["severity"]])
    if f.get("threat_like"):
        like = f"%{f['threat_like']}%"
        where.append("(threat_type LIKE ? OR event_type LIKE ? OR username LIKE ?)")
        params.extend([like, like, like])
    if f.get("auth_events"):
        where.append("event_type LIKE '%auth%'")
    if f.get("has_pii"):
        where.append("pii_json != '[]'")
    if f.get("ioc_type"):
        where.append(
            "EXISTS (SELECT 1 FROM json_each(events.iocs_json) j"
            " WHERE json_extract(j.value,'$.type') = ?)")
        params.append(f["ioc_type"])
    if f.get("q"):
        like = f"%{f['q']}%"
        where.append("(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR username LIKE ?)")
        params.extend([like] * 4)
    if f.get("since_minutes"):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=f["since_minutes"])
                  ).isoformat().replace("+00:00", "Z")
        where.append("ts >= ?")
        params.append(cutoff)
    elif f.get("since_today"):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00")
        where.append("ts >= ?")
        params.append(today)

    fallback = bool(f.get("fallback_text"))
    if fallback:
        words = [w for w in body.text.split() if len(w) > 3][:3]
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
            f" WHERE {clause} ORDER BY ts DESC LIMIT 25",
            params).fetchall()

    policy = dict(load_policy())
    events = []
    for r in rows:
        d = dict(r)
        d["message"], _ = apply_policy(d.get("message") or "", policy)
        events.append(d)

    return {
        "query": body.text,
        "chips": parsed["chips"],
        "note": ("no structured intent found — used fallback text match"
                 if fallback else None),
        "total": total,
        "events": events,
    }
