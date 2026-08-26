import json

from fastapi import APIRouter, HTTPException

from core.storage import db
from detection.engine import load_rules, reload_rules
from privacy.policy_engine import load_policy
from privacy.redactor import sanitize_event

router = APIRouter()


@router.get("/detections/{job_id}")
def job_detections(job_id: str):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM detections WHERE job_id = ? ORDER BY risk_score DESC, id",
            (job_id,),
        ).fetchall()
    policy = dict(load_policy())
    out = []
    for r in rows:
        d = dict(r)
        for col in ("evidence_json", "techniques_json", "reasons_json"):
            d[col.replace("_json", "")] = json.loads(d.pop(col) or "[]")
        out.append(sanitize_event(d, policy))
    return {"job_id": job_id, "detections": out}


@router.get("/rules")
def list_rules():
    return {"rules": [
        {k: v for k, v in r.items() if k != "regex"} | {"has_regex": r.get("regex") is not None}
        for r in load_rules()
    ]}


@router.post("/rules/reload")
def reload_rules_route():
    return {"count": reload_rules()}
