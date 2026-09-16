from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from core.rbac import require_role
from core.storage import db
from streaming import simulator

router = APIRouter()


class StreamStart(BaseModel):
    interval_ms: int = Field(default=1000, ge=50, le=30000)
    lines_per_tick: int = Field(default=5, ge=1, le=200)


@router.post("/stream/start")
async def stream_start(body: StreamStart, _: dict = Depends(require_role("analyst"))):
    return simulator.start_stream(body.interval_ms, body.lines_per_tick)


@router.post("/stream/stop")
async def stream_stop(_: dict = Depends(require_role("analyst"))):
    return simulator.stop_stream()


@router.get("/stream/status")
def stream_status():
    return simulator.status()


@router.get("/stream/recent")
def stream_recent(limit: int = 50, severity: str | None = None):
    """Most recent events for the event wall.

    Scoped to the active stream job when one is running, otherwise the most
    recently created job — so the wall always scrolls live data without
    re-running the pipeline.
    """
    st = simulator.status()
    job_id = st.get("job_id")
    with db() as conn:
        if not job_id:
            row = conn.execute(
                "SELECT id FROM jobs ORDER BY created_at DESC, id DESC LIMIT 1").fetchone()
            job_id = row["id"] if row else None
        if not job_id:
            return {"events": [], "running": False, "job_id": None,
                    "lines_emitted": 0}
        params: list = [job_id]
        where = "job_id = ?"
        if severity:
            where += " AND severity = ?"
            params.append(severity.upper())
        params.append(max(1, min(500, limit)))
        rows = conn.execute(
            f"SELECT event_id, ts, source, event_type, src_ip, dst_ip, severity,"
            f" message, threat_type, risk_score FROM events WHERE {where}"
            f" ORDER BY id DESC LIMIT ?", params).fetchall()
    from core.crypto import decrypt_text
    out = [dict(r) for r in rows]
    for d in out:
        d["message"] = decrypt_text(d.get("message"))
    return {
        "events": out,
        "running": st["running"],
        "job_id": job_id,
        "lines_emitted": st["lines_emitted"],
    }