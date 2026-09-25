import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core import triage
from core import response as soar
from core.rbac import require_role
from core.storage import db
from core.timeline import build_timeline
from privacy.policy_engine import load_policy
from privacy.redactor import sanitize_event
from detection.describe import describe_incident
from detection.kgraph import (event_map, incident_rows, incident_signal_vector)

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
    # M5 item 3: recommended & simulated response actions (playbook lookup).
    # Every per-incident enrichment is best-effort: one failing incident must
    # never 500 the whole job view, so each call is guarded individually.
    for inc in incidents:
        try:
            inc["recommended_actions"] = soar.recommended_actions(inc.get("category") or "")
        except Exception:
            inc["recommended_actions"] = []
    # Workstream B: plain-language "what was found" narrative per incident,
    # generated deterministically from the incident's own computed evidence.
    try:
        krows = incident_rows(job_id)
        eids = sorted({e for i in krows for e in i["event_ids"]})
        events_by_id = event_map(job_id, eids)
        sigs = {i["id"]: incident_signal_vector(i, events_by_id) for i in krows}
    except Exception:
        sigs = {}
    for inc in incidents:
        try:
            inc["description"] = describe_incident(inc, sigs.get(inc.get("id")))
        except Exception:
            inc["description"] = None
    # M4 item 10: optional AI narration of an ALREADY-computed risk breakdown.
    # Narrations are intentionally NOT computed on the list hot path — a live
    # local LLM can cost seconds per incident and would stall the whole tab.
    # The frontend fetches each card's narration lazily instead (see the
    # GET /threats/{incident_id}/narration endpoint below).
    dets = []
    for r in det_rows:
        d = dict(r)
        d["redaction_status"] = "applied"
        dets.append(d)
    return {"job_id": job_id, "incidents": incidents, "detections": dets}


@router.post("/threats/{incident_id}/status")
def incident_status(incident_id: int, body: StatusBody,
                    _: dict = Depends(require_role("analyst"))):
    try:
        updated = triage.set_status(incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if updated is None:
        raise HTTPException(404, "Incident not found")
    return _row_to_incident(updated)


@router.post("/threats/{incident_id}/note")
def incident_note(incident_id: int, body: NoteBody,
                  _: dict = Depends(require_role("analyst"))):
    try:
        updated = triage.add_note(incident_id, body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if updated is None:
        raise HTTPException(404, "Incident not found")
    return _row_to_incident(updated)


@router.post("/threats/{incident_id}/assign")
def incident_assign(incident_id: int, body: AssignBody,
                    _: dict = Depends(require_role("analyst"))):
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


@router.get("/incidents/{incident_id}/actions")
def incident_actions(incident_id: int):
    """Simulated-action history. Read-only; simulation itself is analyst+."""
    return {"incident_id": incident_id, "actions": soar.list_actions(incident_id)}


@router.get("/threats/{incident_id}/narration")
def incident_narration(incident_id: int):
    """Lazily narrate an ALREADY-computed risk breakdown for one incident.

    Optional (M4 item 10): returns an absent/empty body whenever the AI
    switch is off, no local model answers, or narration fails — callers must
    treat that as normal and fall back to the deterministic card. Loaded off
    the list hot path so the threats tab stays fast even with a live model.
    """
    from ai.summary import narrate_risk

    with db() as conn:
        row = conn.execute("SELECT * FROM correlations WHERE id = ?",
                           (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Incident not found")
    inc = sanitize_event(_row_to_incident(row), dict(load_policy()))
    try:
        narration = narrate_risk(str(inc.get("title") or inc.get("entity") or "incident"),
                                 int(inc.get("risk_score") or 0),
                                 list(inc.get("reasons") or []))
    except Exception:
        narration = None
    if not narration:
        return {}
    return {"ai_summary": narration}


@router.post("/incidents/{incident_id}/actions/{action_id}/simulate")
def simulate_incident_action(incident_id: int, action_id: str,
                             user: dict = Depends(require_role("analyst"))):
    """Record a labelled SIMULATED response. No network/system side effect."""
    try:
        rec = soar.simulate_action(incident_id, action_id, user["username"])
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return rec
