"""Job lifecycle management. Jobs track ingestion -> export progress."""

import json
import uuid
from datetime import datetime, timezone

from core.storage import db


def new_id() -> str:
    return uuid.uuid4().hex


def create_job(filename: str, size_bytes: int, source_type: str = "upload") -> str:
    job_id = new_id()
    with db() as conn:
        conn.execute(
            "INSERT INTO jobs (id, filename, size_bytes, source_type, status) VALUES (?, ?, ?, ?, 'pending')",
            (job_id, filename, size_bytes, source_type),
        )
    return job_id


def update_job(job_id: str, **fields) -> None:
    if not fields:
        return
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    cols = ", ".join(f"{k} = ?" for k in fields)
    with db() as conn:
        conn.execute(f"UPDATE jobs SET {cols} WHERE id = ?", (*fields.values(), job_id))


STAGES = [
    "uploaded",
    "detected",
    "parsed",
    "normalized",
    "ioc_extracted",
    "correlated",
    "classified",
    "redacted",
    "exported",
]


def set_stage(job_id: str, stage: str, progress: float | None = None) -> None:
    fields = {"stage": stage}
    if progress is not None:
        fields["progress"] = max(0.0, min(100.0, float(progress)))
    update_job(job_id, **fields)


def merge_stats(job_id: str, **stats) -> dict:
    with db() as conn:
        row = conn.execute("SELECT stats_json FROM jobs WHERE id = ?", (job_id,)).fetchone()
        current = json.loads(row["stats_json"] or "{}") if row else {}
    current.update(stats)
    update_job(job_id, stats_json=json.dumps(current))
    return current


def fail_job(job_id: str, error: str) -> None:
    update_job(job_id, status="error", error=error[:2000])


def finish_job(job_id: str) -> None:
    update_job(job_id, status="done", progress=100.0)
