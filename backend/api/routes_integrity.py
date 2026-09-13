"""Chain-of-custody API: verify a job's batch hash chain."""

from fastapi import APIRouter, HTTPException

from core.hashchain import verify_integrity
from core.storage import db

router = APIRouter()


@router.get("/integrity/{job_id}")
def integrity(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?",
                        (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    return verify_integrity(job_id)
