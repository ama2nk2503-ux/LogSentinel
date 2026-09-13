"""M4: deterministic idempotent event identity tests.

Covers: stable hash of (timestamp|hostname|process|raw_text), constant marker
when no timestamp is parseable, timestamp_source "event" vs "ingest",
pipeline end-to-end persistence, and the idempotent backfill.
"""

import pytest

from core.dedup_backfill import backfill_dedup_ids
from core.storage import db
from normalization.identity import NO_TS_MARKER, deterministic_event_id
from normalization.normalizer import normalize
from parsers.load_all import *  # noqa: F401,F403
from parsers.registry import get_line_parser
from tests.test_detection import insert_event


# ---------- pure identity function ----------

def test_dedup_id_is_deterministic():
    a = deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "sshd", "raw line")
    b = deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "sshd", "raw line")
    assert a == b and len(a) == 32


def test_dedup_id_changes_with_any_component():
    base = deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "sshd", "raw line")
    assert deterministic_event_id("2026-08-25T10:30:02Z", "srv1", "sshd", "raw line") != base
    assert deterministic_event_id("2026-08-25T10:30:01Z", "srv2", "sshd", "raw line") != base
    assert deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "cron", "raw line") != base
    assert deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "sshd", "other line") != base


def test_dedup_id_constant_marker_without_timestamp():
    with_ts = deterministic_event_id("", "srv1", "sshd", "no time here")
    assert with_ts == deterministic_event_id(NO_TS_MARKER, "srv1", "sshd", "no time here")
    # still differs from every timestamped id
    assert with_ts != deterministic_event_id("2026-08-25T10:30:01Z", "srv1", "sshd", "no time here")


# ---------- normalizer wiring ----------

def test_normalize_event_ts_marks_source_event():
    fields = get_line_parser("syslog")(
        "Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")
    ev = normalize(fields, "j_dedup", 1, "Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")
    assert ev.timestamp.endswith("Z")
    assert ev.timestamp_source == "event"
    assert ev.dedup_event_id
    assert ev.dedup_event_id == deterministic_event_id(
        ev.timestamp, ev.hostname, ev.source,
        "Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")


def test_normalize_no_ts_marks_source_ingest():
    ev = normalize({"event_type": "kv_noise"}, "j_dedup", 2, "SRC=1.2.3.4 DST=5.6.7.8")
    assert ev.timestamp == ""
    assert ev.timestamp_source == "ingest"
    assert ev.dedup_event_id == deterministic_event_id(
        "", "", "", "SRC=1.2.3.4 DST=5.6.7.8")


def test_normalize_same_raw_line_same_identity():
    raw = "Aug 25 10:31:00 web01 sshd[2041]: Accepted publickey for deploy from 10.0.0.5"
    fields = get_line_parser("syslog")(raw)
    ev1 = normalize(fields, "jobA", 1, raw)
    ev2 = normalize(fields, "jobB", 99, raw)   # different job/line -> same identity
    assert ev1.dedup_event_id == ev2.dedup_event_id


# ---------- pipeline end-to-end ----------

def test_pipeline_persists_dedup_and_timestamp_source():
    from core import jobs, pipeline
    from core.config import settings

    job_id = jobs.create_job("dedup_e2e.log", 0)
    body = (
        "Aug 25 09:05:01 srv01 sshd: Failed password for admin from 185.23.45.67\n"
        "SRC=185.23.45.67 DST=10.0.0.15 PROTO=TCP DPT=22 ACTION=DENY\n"
    )
    path = settings.upload_dir / f"{job_id}__dedup_e2e.log"
    path.write_text(body, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()
    with db() as conn:
        rows = conn.execute(
            "SELECT ts, raw_hint, dedup_event_id, timestamp_source FROM ("
            " SELECT e.ts, e.dedup_event_id, e.timestamp_source, e.message AS raw_hint"
            " FROM events e WHERE job_id = ? ORDER BY e.id)",
            (job_id,)).fetchall()
    assert len(rows) == 2
    syslog_row = next(r for r in rows if r["ts"])
    kv_row = next(r for r in rows if not r["ts"])
    assert syslog_row["timestamp_source"] == "event"
    assert syslog_row["dedup_event_id"]
    assert kv_row["timestamp_source"] == "ingest"
    assert kv_row["dedup_event_id"]


def test_backfill_fills_missing_ids_and_is_idempotent():
    job = "t_dedup_bf"
    insert_event(job, line_no=1, ts="2026-08-25T19:00:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", hostname="srv1", source="sshd",
                 message="Failed password for admin")
    insert_event(job, event_type="kv_noise", message="SRC=1.2.3.4 DST=5.6.7.8")
    # seed raw_lines for the first event so the join path is exercised
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO raw_lines (job_id, line_no, raw) VALUES (?, ?, ?)",
            (job, 1, "Aug 25 19:00:00 srv1 sshd: Failed password for admin"))

    n = backfill_dedup_ids()
    assert n >= 2
    with db() as conn:
        rows = conn.execute(
            "SELECT ts, hostname, source, message, dedup_event_id, timestamp_source"
            " FROM events WHERE job_id = ?", (job,)).fetchall()
    by_msg = {r["message"]: r for r in rows}
    r1 = by_msg["Failed password for admin"]
    assert r1["dedup_event_id"] == deterministic_event_id(
        r1["ts"], r1["hostname"], r1["source"],
        "Aug 25 19:00:00 srv1 sshd: Failed password for admin")
    assert r1["timestamp_source"] == "event"
    r2 = by_msg["SRC=1.2.3.4 DST=5.6.7.8"]
    assert r2["timestamp_source"] == "ingest"
    assert r2["dedup_event_id"] == deterministic_event_id(
        "", "", "", "SRC=1.2.3.4 DST=5.6.7.8")

    # running again must change nothing (idempotent)
    assert backfill_dedup_ids() == 0


def test_backfill_never_touches_event_id():
    job = "t_dedup_keep"
    insert_event(job, event_id="fixed-id-42", ts="2026-08-25T20:00:00Z",
                 event_type="auth_failure", message="x")
    backfill_dedup_ids()
    with db() as conn:
        row = conn.execute(
            "SELECT event_id, dedup_event_id FROM events WHERE job_id = ?",
            (job,)).fetchone()
    assert row["event_id"] == "fixed-id-42"
    assert row["dedup_event_id"]
