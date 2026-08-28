from fastapi import APIRouter, HTTPException

from core import compliance
from core.storage import db

router = APIRouter()


def _job_exists(job_id: str) -> bool:
    with db() as conn:
        return conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is not None


@router.get("/audit/frameworks")
def audit_frameworks():
    out = []
    for f in compliance.list_frameworks():
        out.append({"name": f["name"], "description": f["description"],
                    "controls": len(f.get("controls", []))})
    return {"frameworks": out}


@router.get("/audit/{job_id}")
def audit_job(job_id: str):
    if not _job_exists(job_id):
        raise HTTPException(404, "Job not found")
    results = compliance.audit_job(job_id)
    return {
        "job_id": job_id,
        "frameworks": results,
        "summary": {
            "frameworks": len(results),
            "passed": sum(1 for r in results if r["status"] == "PASS"),
            "warned": sum(1 for r in results if r["status"] == "WARN"),
            "failed": sum(1 for r in results if r["status"] == "FAIL"),
        },
    }


@router.get("/audit/results")
def audit_history(job_id: str | None = None):
    return {"audits": compliance.audit_history(job_id)}


@router.get("/audit/report/{job_id}/{framework_name:path}")
def audit_report(job_id: str, framework_name: str):
    if not _job_exists(job_id):
        raise HTTPException(404, "Job not found")
    try:
        report = compliance.render_report(job_id, framework_name)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"job_id": job_id, "framework": framework_name,
            "format": "markdown", "report": report}