from fastapi import APIRouter

from core.benchmark import latest_results, run_benchmark

router = APIRouter()


@router.post("/benchmark/run")
def start_benchmark():
    return run_benchmark()


@router.get("/benchmark/results")
def get_results():
    r = latest_results()
    return {"has_run": r is not None, "results": r}
