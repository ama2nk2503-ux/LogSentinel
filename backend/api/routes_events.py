import json

from fastapi import APIRouter, HTTPException, Query

from core.storage import db
from privacy.policy_engine import load_policy
from privacy.redactor import sanitize_event

router = APIRouter()

EVENT_COLS = ("id", "event_id", "job_id", "line_no", "ts", "event_type", "source",
              "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "username",
              "hostname", "action", "status", "severity", "message", "threat_type",
              "risk_score", "anomaly_score", "anomalous")


def _serialize(row, full=False):
    d = dict(row)


@router.get("/events")
def list_events(
    job_id: str | None = None,
    severity: str | None = None,
    threat: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    where, params = ["1=1"], []
    if job_id:
        where.append("job_id = ?")
        params.append(job_id)
    if severity:
        where.append("severity = ?")
        params.append(severity.upper())
    if threat:
        where.append("threat_type = ?")
        params.append(threat)
    if q:
        where.append("(message LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR username LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like])
    clause = " AND ".join(where)

    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM events WHERE {clause}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT {', '.join(EVENT_COLS)} FROM events WHERE {clause}"
            " ORDER BY id LIMIT ? OFFSET ?",
            (*params, page_size, (page - 1) * page_size),
        ).fetchall()
    policy = load_policy()
    return {"total": total, "page": page, "page_size": page_size,
            "events": [sanitize_event(dict(r), dict(policy)) for r in rows]}


@router.get("/events/{event_id}")
def event_detail(event_id: str):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM events WHERE event_id = ? OR id = ?",
            (event_id, int(event_id) if event_id.isdigit() else -1),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Event not found")
    d = dict(row)
    for col in ("iocs_json", "pii_json", "attack_json"):
        d[col.replace("_json", "")] = json.loads(d.pop(col) or "[]")
    d["mappings"] = json.loads(d.pop("mappings_json") or "{}")
    d["extras"] = json.loads(d.pop("extras_json") or "{}")
    raw = conn.execute(
        "SELECT raw FROM raw_lines WHERE job_id = ? AND line_no = ?",
        (d["job_id"], d["line_no"]),
    ).fetchone()
    d["raw_line"] = raw["raw"] if raw else None
    d["redaction_status"] = "applied" if load_policy() else "none"
    return sanitize_event(d, dict(load_policy()))
