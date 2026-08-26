"""Upload & paste endpoints with strict validation."""

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from core import jobs
from core.config import settings
from core.ingest import ValidationError, save_stream, validate_extension
from core.pipeline import run_job

router = APIRouter()


def _launch(job_id: str, bg: BackgroundTasks) -> dict:
    jobs.update_job(job_id, status="queued")
    bg.add_task(run_job, job_id)
    return {"job_id": job_id}


@router.post("/upload")
async def upload(files: list[UploadFile] = File(...), bg: BackgroundTasks = None):
    if not files or len(files) > 20:
        raise HTTPException(400, "Provide 1-20 files")
    created = []
    for f in files:
        try:
            validate_extension(f.filename or "")
        except ValidationError as e:
            raise HTTPException(400, f"{f.filename}: {e}") from e
        job_id = jobs.create_job(f.filename, 0, source_type="upload")

        def sync_chunks(upload=f):
            try:
                while True:
                    piece = upload.file.read(1024 * 1024)
                    if not piece:
                        return
                    yield piece
            finally:
                upload.file.close()

        try:
            dest, size = save_stream(job_id, f.filename, sync_chunks())
        except ValidationError as e:
            jobs.update_job(job_id, status="error", error=str(e)[:2000])
            raise HTTPException(400, str(e)) from e
        jobs.update_job(job_id, size_bytes=size)
        created.append(_launch(job_id, bg))
    return {"jobs": created}


class PasteBody(BaseModel):
    text: str = Field(min_length=1, max_length=settings.max_upload_mb * 1024 * 1024)
    name: str = Field(default="pasted.txt", max_length=120)


@router.post("/paste")
def paste(body: PasteBody, bg: BackgroundTasks):
    job_id = jobs.create_job(body.name, 0, source_type="paste")
    payload = body.text.encode("utf-8", errors="replace")
    try:
        dest, size = save_stream(job_id, body.name, [payload])
    except ValidationError as e:
        jobs.update_job(job_id, status="error", error=str(e)[:2000])
        raise HTTPException(400, str(e)) from e
    jobs.update_job(job_id, size_bytes=size)
    return _launch(job_id, bg)
