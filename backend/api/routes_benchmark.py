from fastapi import APIRouter, Depends

from core.benchmark import latest_results, run_benchmark
from core.rbac import require_role

router = APIRouter()


@router.post("/benchmark/run")
def start_benchmark(_: dict = Depends(require_role("analyst"))):
    return run_benchmark()


@router.get("/benchmark/results")
def get_results():
    r = latest_results()
    return {"has_run": r is not None, "results": r}
