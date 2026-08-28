from fastapi import APIRouter, HTTPException

from core.assets import build_assets, list_assets
from core.storage import db

router = APIRouter()

CRITICALITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _job_exists(job_id: str) -> bool:
    with db() as conn:
        return conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is not None


@router.get("/assets/{job_id}")
def job_assets(job_id: str):
    if not _job_exists(job_id):
        raise HTTPException(404, "Job not found")
    assets = list_assets(job_id)
    if not assets:
        build_assets(job_id)
        assets = list_assets(job_id)
    by_type: dict[str, int] = {}
    by_criticality: dict[str, int] = {}
    for a in assets:
        by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
        by_criticality[a["criticality"]] = by_criticality.get(a["criticality"], 0) + 1
    return {
        "job_id": job_id,
        "total": len(assets),
        "assets": assets,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "by_criticality": {k: by_criticality.get(k, 0)
                           for k in sorted(by_criticality, key=CRITICALITY_ORDER.get)},
        "critical_count": sum(1 for a in assets if a["criticality"] in ("HIGH", "CRITICAL")),
    }