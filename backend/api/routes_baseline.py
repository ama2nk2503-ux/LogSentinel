from fastapi import APIRouter, Depends, HTTPException, Query

from core.baseline import job_anomalies, list_baseline, rebuild_baseline
from core.rbac import require_role

router = APIRouter()


@router.get("/baseline")
def get_baseline(
    entity_type: str | None = None,
    entity: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    return list_baseline(entity_type=entity_type, entity=entity, limit=limit, offset=offset)


@router.get("/baseline/anomalies")
def get_baseline_anomalies(
    job_id: str,
    top: int = Query(20, ge=1, le=200),
    min_z: float = Query(2.0, ge=0.0),
):
    return job_anomalies(job_id, top=top, min_z=min_z)


@router.post("/baseline/rebuild")
def post_baseline_rebuild(
    reset: bool = Query(False),
    _: dict = Depends(require_role("analyst")),
):
    if reset:
        return rebuild_baseline(reset=True)
    return rebuild_baseline(reset=False)


@router.get("/baseline/jobs")
def get_baseline_jobs(_: dict = Depends(require_role("analyst"))):
    from core.storage import db

    with db() as conn:
        jobs = conn.execute(
            "SELECT bj.job_id, bj.folded_at, j.filename FROM baseline_jobs bj "
            "JOIN jobs j ON j.id = bj.job_id ORDER BY bj.folded_at DESC"
        ).fetchall()
    return {"jobs": [dict(r) for r in jobs]}