"""M4: chain-of-custody hash chain — append, verify, tamper detection."""

import pytest

from core.hashchain import append_batch, verify_integrity
from core.storage import db
from tests.test_detection import insert_event


def _flush_batch(job_id: str, msg: str = "Failed password for admin") -> None:
    """Simulate a pipeline batch insert + chain append in one transaction."""
    with db() as conn:
        conn.execute(
            "INSERT INTO events (event_id, job_id, line_no, ts, event_type,"
            " src_ip, severity, message) VALUES (?,?,?,?,?,?,?,?)",
            (f"ev_{job_id}_{msg[:8]}", job_id, 1, "2026-08-25T10:00:00Z",
             "auth_failure", "185.23.45.67", "HIGH", msg))
        append_batch(conn, job_id)


def test_chain_appends_and_verifies(tmp_path):
    job = "hc_ok"
    _flush_batch(job)
    _flush_batch(job)
    _flush_batch(job)
    res = verify_integrity(job)
    assert res["valid"] is True
    assert res["batches"] >= 3
    assert res["events_covered"] >= 3
    assert res["problems"] == []


def test_verify_detects_tampered_evidence():
    job = "hc_tamper"
    _flush_batch(job)
    _flush_batch(job)
    assert verify_integrity(job)["valid"]
    # tamper with a stored event after the chain was built
    with db() as conn:
        conn.execute("UPDATE events SET message = 'benign clean line' WHERE job_id = ?",
                     (job,))
    res = verify_integrity(job)
    assert res["valid"] is False
    assert any("batch hash mismatch" in p["issue"] for p in res["problems"])


def test_verify_detects_deleted_link():
    job = "hc_del"
    _flush_batch(job, "attempt one")
    _flush_batch(job, "attempt two")
    _flush_batch(job, "attempt three")
    with db() as conn:
        conn.execute("DELETE FROM hash_chain WHERE job_id = ? AND batch_no = 2", (job,))
    res = verify_integrity(job)
    assert res["valid"] is False
    assert any("prev_hash mismatch" in p["issue"] for p in res["problems"])


def test_empty_job_has_valid_empty_chain():
    res = verify_integrity("hc_never_existed")
    assert res["valid"] is True and res["batches"] == 0


def test_integrity_endpoint(monkeypatch):
    from api.routes_integrity import integrity as ep
    from core import jobs
    from fastapi import HTTPException

    job = jobs.create_job("hc_api.log", 0)
    _flush_batch(job, "endpoint check")
    assert ep(job)["valid"] is True
    with pytest.raises(HTTPException):
        ep("no_such_job_hc")


def test_chain_append_never_raises_into_ingestion(monkeypatch):
    job = "hc_guard"
    from core import hashchain

    def boom(*a, **k):
        raise RuntimeError("hashing exploded")

    monkeypatch.setattr(hashchain, "_batch_hash", boom)
    with db() as conn:
        conn.execute(
            "INSERT INTO events (event_id, job_id, line_no, ts, event_type,"
            " src_ip, severity, message) VALUES (?,?,?,?,?,?,?,?)",
            ("ev_guard", job, 1, "2026-08-25T10:00:00Z", "auth_failure",
             "185.23.45.67", "HIGH", "Failed password"))
        hashchain.append_batch(conn, job)  # must not raise
    with db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM events WHERE job_id = ?",
                         (job,)).fetchone()["c"]
    assert n == 1, "event insert must survive chain failure"
