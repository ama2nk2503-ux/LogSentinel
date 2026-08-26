from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response

from core import jobs
from core.storage import db
from exporters.exporters import EXPORTERS
from exporters.validator import ExportValidationError, validate_export

router = APIRouter()

MEDIA = {
    "json": "application/json",
    "csv": "text/csv",
    "cef": "text/plain",
    "leef": "text/plain",
    "stix": "application/json",
    "syslog": "text/plain",
}


@router.post("/export/{job_id}")
@router.get("/export/{job_id}")
def export_job(job_id: str, format: str = "json"):
    fmt = format.lower().strip()
    exporter = EXPORTERS.get(fmt)
    if exporter is None:
        raise HTTPException(400, f"Unsupported format '{format}'. "
                                 f"Supported: {sorted(EXPORTERS)}")
    with db() as conn:
        job = conn.execute(
            "SELECT id, status FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if job is None:
        raise HTTPException(404, "Job not found")

    try:
        payload = exporter(job_id)
        validate_export(fmt, payload)
    except ExportValidationError as e:
        raise HTTPException(500, f"Export validation failed: {e}") from e

    if job["status"] == "done":
        jobs.update_job(job_id, stage="exported")

    ext = {"cef": "txt", "leef": "txt", "syslog": "log"}.get(fmt, fmt)
    filename = f"logsentinel_{job_id[:8]}.{ext}"
    return PlainTextResponse(
        payload,
        media_type=MEDIA[fmt],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/formats")
def formats():
    return {"formats": sorted(EXPORTERS)}


@router.get("/report/{job_id}")
def pdf_report(job_id: str):
    from exporters.pdf_report import generate_pdf
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id=?",
                        (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")
    try:
        data = generate_pdf(job_id)
    except ValueError as e:
        raise HTTPException(500, f"Report generation failed: {e}") from e
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="logsentinel_report_{job_id[:8]}.pdf"'},
    )
