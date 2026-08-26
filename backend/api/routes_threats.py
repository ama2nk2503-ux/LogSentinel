import json

from fastapi import APIRouter, HTTPException

from core.storage import db
from privacy.policy_engine import load_policy
from privacy.redactor import sanitize_event

router = APIRouter()


def _row_to_incident(r) -> dict:
    d = dict(r)
    for col in ("reasons_json", "evidence_event_ids_json", "timeline_json",
                "techniques_json", "killchain_json"):
        key = col.replace("_json", "")
        raw = d.pop(col)
        if col == "killchain_json":
            d[key] = __import__("json").loads(raw or "{}")
        else:
            d[key] = __import__("json").loads(raw or "[]")
    return d


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
