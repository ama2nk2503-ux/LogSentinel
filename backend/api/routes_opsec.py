"""OPSEC actor attribution API (Workstream A) + actor narratives (B)."""

from fastapi import APIRouter, HTTPException

from core.storage import db
from detection.describe import describe_actor
from detection.opsec import build_actor_groups

router = APIRouter()


@router.get("/opsec/{job_id}")
def opsec_actors(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    result = build_actor_groups(job_id)
    for actor in result.get("actors", []):
        actor["description"] = describe_actor(actor)
    return result