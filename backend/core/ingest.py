"""Safe file ingestion: validation, capped streaming save, chunked reading."""

from pathlib import Path
from typing import Iterator

from core.config import settings


class ValidationError(Exception):
    pass


def validate_extension(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise ValidationError(f"Extension '{ext or '(none)'}' not allowed. "
                              f"Allowed: {sorted(settings.allowed_extensions)}")
    return ext


def sanitize_filename(filename: str) -> str:
    """Strip any directory components and hostile characters; keep readable base."""
    base = Path(filename.replace("\\", "/")).name
    base = "".join(c if c.isalnum() or c in "._- " else "_" for c in base).strip()
    return base[:120] or "unnamed"


def max_bytes() -> int:
    return settings.max_upload_mb * 1024 * 1024


def save_stream(job_id: str, filename: str, chunks) -> tuple[Path, int]:
    """Stream incoming chunks to disk under a UUID-prefixed name, enforcing size cap."""
    dest = settings.upload_dir / f"{job_id}__{sanitize_filename(filename)}"
    written = 0
    cap = max_bytes()
    with open(dest, "wb") as out:
        for chunk in chunks:
            written += len(chunk)
            if written > cap:
                out.close()
                dest.unlink(missing_ok=True)
                raise ValidationError(f"File exceeds {settings.max_upload_mb} MB limit")
            out.write(chunk)
    if written == 0:
        dest.unlink(missing_ok=True)
        raise ValidationError("Empty file rejected")
    return dest, written


def iter_line_chunks(path: Path, chunk_lines: int | None = None) -> Iterator[list[str]]:
    """Yield lists of lines (~chunk_lines each) so RAM stays flat on huge files."""
    size = chunk_lines or settings.chunk_lines
    batch: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            batch.append(line.rstrip("\r\n"))
            if len(batch) >= size:
                yield batch
                batch = []
    if batch:
        yield batch
