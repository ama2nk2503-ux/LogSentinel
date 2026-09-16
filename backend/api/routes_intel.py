from fastapi import APIRouter, Depends, HTTPException

from core import intel
from core.rbac import require_role
from core.storage import db
from intelligence.aggregator import build_intel

router = APIRouter()


@router.get("/intel/reputation/{value:path}")
def reputation(value: str):
    """Reputation verdict for any value (reference feed + sighted indicators)."""
    return intel.reputation(value)


@router.get("/intel/reference")
def intel_reference():
    return {"count": len(intel.list_reference()),
            "indicators": intel.list_reference()}


@router.post("/intel/reference/reload")
def reload_reference(_: dict = Depends(require_role("analyst"))):
    count = intel.reload_intel_reference()
    return {"reloaded": True, "count": count}


@router.get("/intel/{job_id}")
def job_intel(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    return build_intel(job_id)