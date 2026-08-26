from fastapi import APIRouter
from pydantic import BaseModel, Field

from streaming import simulator

router = APIRouter()


class StreamStart(BaseModel):
    interval_ms: int = Field(default=1000, ge=50, le=30000)
    lines_per_tick: int = Field(default=5, ge=1, le=200)


@router.post("/stream/start")
async def stream_start(body: StreamStart):
    return simulator.start_stream(body.interval_ms, body.lines_per_tick)


@router.post("/stream/stop")
async def stream_stop():
    return simulator.stop_stream()


@router.get("/stream/status")
def stream_status():
    return simulator.status()
