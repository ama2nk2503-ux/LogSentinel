"""Incident triage: analyst workflow over correlated incidents.

Statuses follow a deterministic lifecycle; false-positive feedback is fed
back into risk scoring so re-correlation reflects the analyst's verdict.
"""

import json
from datetime import datetime, timezone

from core.storage import db

STATUSES = ("NEW", "ACKNOWLEDGED", "IN_PROGRESS", "ESCALATED",
            "RESOLVED", "FALSE_POSITIVE")
GATING_STATUSES = ("NEW", "ACKNOWLEDGED", "IN_PROGRESS", "ESCALATED")

FP_THRESHOLD_HOURS = 24


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _incident(conn, incident_id: int) -> dict | None:
    row = conn.execute(
        "SELECT * FROM correlations WHERE id = ?", (incident_id,)).fetchone()
    return dict(row) if row else None


def set_status(incident_id: int, status: str) -> dict | None:
    status = status.upper()
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    now = _now()
    with db() as conn:
        inc = _incident(conn, incident_id)
        if inc is None:
            return None
        if status == "FALSE_POSITIVE":
            _apply_fp_feedback(conn, inc)
        conn.execute(
            "UPDATE correlations SET status = ?,"
            " acknowledged_at = CASE WHEN ? = 'ACKNOWLEDGED' AND acknowledged_at IS NULL"
            "                          THEN ? ELSE acknowledged_at END,"
            " resolved_at = CASE WHEN ? IN ('RESOLVED','FALSE_POSITIVE')"
            "                     THEN ? ELSE resolved_at END"
            " WHERE id = ?",
            (status, status, now, status, now, incident_id))
    return _load(incident_id)


def _apply_fp_feedback(conn, inc: dict) -> None:
    """Downgrade + annotate the incident itself (analyst verdict persists)."""
    reasons = json.loads(inc["reasons_json"] or "[]")
    if not any("false-positive" in r for r in reasons):
        reasons.append("+ false-positive feedback: risk suppressed by analyst")
    conn.execute(
        "UPDATE correlations SET false_positive = 1, risk_score = MAX(1, ?),"
        " reasons_json = ? WHERE id = ?",
        (max(1, (inc["risk_score"] or 0) // 2), json.dumps(reasons), inc["id"]))


def add_note(incident_id: int, note: str) -> dict | None:
    note = note.strip()
    if not note:
        raise ValueError("note cannot be empty")
    with db() as conn:
        inc = _incident(conn, incident_id)
        if inc is None:
            return None
        notes = json.loads(inc["notes_json"] or "[]")
        notes.append({"at": _now(), "note": note})
        conn.execute("UPDATE correlations SET notes_json = ? WHERE id = ?",
                     (json.dumps(notes), incident_id))
    return _load(incident_id)


def assign(incident_id: int, assignee: str) -> dict | None:
    assignee = assignee.strip()
    with db() as conn:
        if _incident(conn, incident_id) is None:
            return None
        conn.execute("UPDATE correlations SET assignee = ? WHERE id = ?",
                     (assignee, incident_id))
    return _load(incident_id)


def _load(incident_id: int) -> dict | None:
    with db() as conn:
        return _incident(conn, incident_id)


def summary() -> dict:
    with db() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as c FROM correlations GROUP BY status").fetchall()
        counts = {r["status"] or "NEW": r["c"] for r in rows}
        gating = conn.execute(
            "SELECT created_at, strftime('%s','now') - strftime('%s', created_at) AS age_s"
            " FROM correlations WHERE status IN ('NEW','ACKNOWLEDGED','IN_PROGRESS','ESCALATED')"
            " ORDER BY created_at LIMIT 1").fetchone()
    age_min = round((gating["age_s"] or 0) / 60) if gating else 0
    return {
        "counts": counts,
        "open": sum(counts.get(s, 0) for s in GATING_STATUSES),
        "oldest_open_age_min": age_min,
        "unknown": 0,
    }