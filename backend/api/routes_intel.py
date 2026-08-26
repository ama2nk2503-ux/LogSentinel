from fastapi import APIRouter, HTTPException

from core.storage import db
from intelligence.aggregator import _recommendation, build_intel

router = APIRouter()


@router.get("/intel/{job_id}")
def job_intel(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    return build_intel(job_id)
