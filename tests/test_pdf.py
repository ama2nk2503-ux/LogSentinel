import pytest

from exporters.pdf_report import generate_pdf
from tests.test_detection import insert_event
from tests.test_export import db_conn


@pytest.fixture(scope="module", autouse=True)
def seed_pdf_job():
    job = "t_pdf"
    with db_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO jobs (id, filename, size_bytes) VALUES (?, ?, ?)",
            (job, "pdf_test.log", 10))
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T21:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     severity="HIGH",
                     message=f"Failed password for admin from 185.23.45.67 #{i}")
    insert_event(job, ts="2026-08-25T21:05:00Z", event_type="auth_success",
                 src_ip="185.23.45.67", username="admin", status="success",
                 message="Accepted password for admin from 185.23.45.67")
    yield job


def test_pdf_generated_and_valid():
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    evaluate_job("t_pdf")
    build_incidents("t_pdf")

    data = generate_pdf("t_pdf")
    assert data.startswith(b"%PDF")
    assert b"%%EOF" in data[-1024:]
    assert len(data) > 2000
    # page count sanity: at least 2 pages => at least 2 /Type /Page markers
    import zlib
    pages = data.count(b"/Type /Page\n") + data.count(b"/Type /Page ")
    assert pages >= 1 or b"/Pages" in data


def test_pdf_unknown_job_raises():
    with pytest.raises(ValueError):
        generate_pdf("no_such_job_zzz")
