"""Knowledge graph API (Workstream E): GraphRAG-ready JSON export."""

from fastapi import APIRouter, HTTPException

from core.storage import db
from detection.kgraph import build_job_graph

router = APIRouter()


@router.get("/knowledge/{job_id}")
def job_knowledge_graph(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    return build_job_graph(job_id)