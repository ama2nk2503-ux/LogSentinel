from fastapi import APIRouter, HTTPException

from core.storage import db

router = APIRouter()


@router.get("/ioc/{job_id}")
def job_iocs(job_id: str):
    """Unique validated IOCs for a job with occurrence counts and time span."""
    with db() as conn:
        jobs_row = conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if jobs_row is None:
            raise HTTPException(404, "Job not found")
        rows = conn.execute(
            """
            SELECT json_extract(j.value, '$.value') AS value,
                   json_extract(j.value, '$.type') AS type,
                   COUNT(*) AS occurrences,
                   MIN(e.ts) AS first_seen,
                   MAX(e.ts) AS last_seen
            FROM events e, json_each(e.iocs_json) j
            WHERE e.job_id = ?
            GROUP BY value, type
            ORDER BY occurrences DESC, value
            """,
            (job_id,),
        ).fetchall()
    return {"job_id": job_id, "iocs": [dict(r) for r in rows]}
