import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core import triage
from core.storage import db
from core.timeline import build_timeline
from privacy.policy_engine import load_policy
from privacy.redactor import sanitize_event

router = APIRouter()


def _row_to_incident(r) -> dict:
    d = dict(r)
    for col in ("reasons_json", "evidence_event_ids_json", "timeline_json",
                "techniques_json", "killchain_json", "notes_json"):
        key = col.replace("_json", "")
        raw = d.pop(col)
        if col == "killchain_json":
            d[key] = __import__("json").loads(raw or "{}")
        elif col == "notes_json":
            d[key] = json.loads(raw or "[]")
        else:
            d[key] = __import__("json").loads(raw or "[]")
    return d


class StatusBody(BaseModel):
    status: str


class NoteBody(BaseModel):
    note: str = Field(min_length=1)


class AssignBody(BaseModel):
    assignee: str = Field(min_length=1)


@router.get("/threats/triage/summary")
def triage_summary():
    return triage.summary()


@router.get("/threats/{job_id}")
def job_threats(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
        inc_rows = conn.execute(
            "SELECT * FROM correlations WHERE job_id = ? ORDER BY risk_score DESC",
            (job_id,)).fetchall()
        det_rows = conn.execute(
            "SELECT id, rule_id, rule_name, severity, category, entity,"
            " risk_score FROM detections WHERE job_id = ? ORDER BY risk_score DESC",
            (job_id,)).fetchall()
    policy = dict(load_policy())
    incidents = [sanitize_event(_row_to_incident(r), policy) for r in inc_rows]
    dets = []
    for r in det_rows:
        d = dict(r)
        d["redaction_status"] = "applied"
        dets.append(d)
    return {"job_id": job_id, "incidents": incidents, "detections": dets}


@router.post("/threats/{incident_id}/status")
def incident_status(incident_id: int, body: StatusBody):
    try:
        updated = triage.set_status(incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if updated is None:
        raise HTTPException(404, "Incident not found")
    return _row_to_incident(updated)


@router.post("/threats/{incident_id}/note")
def incident_note(incident_id: int, body: NoteBody):
    try:
        updated = triage.add_note(incident_id, body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if updated is None:
        raise HTTPException(404, "Incident not found")
    return _row_to_incident(updated)


@router.post("/threats/{incident_id}/assign")
def incident_assign(incident_id: int, body: AssignBody):
    updated = triage.assign(incident_id, body.assignee)
    if updated is None:
        raise HTTPException(404, "Incident not found")
    return _row_to_incident(updated)


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: int):
    timeline = build_timeline(incident_id)
    if timeline is None:
        raise HTTPException(404, "Incident not found")
    return timeline
