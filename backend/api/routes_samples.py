"""Sample datasets for demos — read-only, path-traversal safe."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from core.config import settings

router = APIRouter()

SAMPLES_DIR = settings.rules_dir.parent / "samples"


def _safe_path(name: str) -> Path:
    p = (SAMPLES_DIR / Path(name).name).resolve()
    if not str(p).startswith(str(SAMPLES_DIR.resolve())):
        raise HTTPException(400, "Invalid sample name")
    if not p.is_file():
        raise HTTPException(404, "Sample not found")
    return p


@router.get("/samples")
def list_samples():
    out = []
    for p in sorted(SAMPLES_DIR.glob("*")) if SAMPLES_DIR.exists() else []:
        if p.is_file():
            out.append({"name": p.name, "size": p.stat().st_size})
    return {"samples": out}


@router.get("/samples/{name}")
def get_sample(name: str):
    return PlainTextResponse(_safe_path(name).read_text(encoding="utf-8", errors="replace"))
