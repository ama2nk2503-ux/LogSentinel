import json

from fastapi import APIRouter, HTTPException

from core.jobs import STAGES
from core.storage import db

router = APIRouter()


@router.get("/jobs")
def list_jobs():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, filename, size_bytes, source_type, status, stage, progress,"
            " detected_format, format_confidence, stats_json, error, created_at"
            " FROM jobs ORDER BY created_at DESC, id DESC LIMIT 100"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["stats"] = json.loads(d.pop("stats_json") or "{}")
        out.append(d)
    return {"jobs": out}


@router.get("/stages")
def stages():
    return {"stages": STAGES}


@router.get("/jobs/{job_id}")
def job_detail(job_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Job not found")
    d = dict(row)
    d["stats"] = json.loads(d.pop("stats_json") or "{}")
    d["stage_index"] = STAGES.index(d["stage"]) if d["stage"] in STAGES else -1
    d["stages"] = STAGES
    return d
