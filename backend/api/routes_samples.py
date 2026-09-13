"""Sample datasets for demos — read-only, path-traversal safe."""

from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from core.config import settings

router = APIRouter()

SAMPLES_DIR = settings.rules_dir.parent / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.yaml"


def _load_manifest() -> list[dict]:
    if not MANIFEST_PATH.is_file():
        return []
    try:
        data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return []
    return data if isinstance(data, list) else []


def _safe_path(name: str) -> Path:
    p = (SAMPLES_DIR / Path(name).name).resolve()
    if not str(p).startswith(str(SAMPLES_DIR.resolve())):
        raise HTTPException(400, "Invalid sample name")
    if not p.is_file():
        raise HTTPException(404, "Sample not found")
    return p


@router.get("/samples")
def list_samples():
    manifest = {m["file"]: m for m in _load_manifest() if m.get("file")}
    out = []
    for p in sorted(SAMPLES_DIR.glob("*")) if SAMPLES_DIR.exists() else []:
        if not p.is_file() or p.name == "manifest.yaml":
            continue
        entry = {"name": p.name, "file": p.name, "size": p.stat().st_size,
                 "scenario": None, "title": p.name, "description": "", "format": None}
        meta = manifest.get(p.name)
        if meta:
            entry["title"] = meta.get("name", p.name)
            entry.update(meta)
        out.append(entry)
    return {"samples": out}


@router.get("/samples/{name}")
def get_sample(name: str):
    return PlainTextResponse(_safe_path(name).read_text(encoding="utf-8", errors="replace"))
