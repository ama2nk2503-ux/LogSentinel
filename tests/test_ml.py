"""In-loop ML anomaly scoring: determinism, flagging, pipeline integration, API."""

import json

import pytest

from api.routes_ml import ml_job
from core import jobs
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from ml import model as mlm
from tests.test_detection import insert_event


def _seed_job(job_id: str, n_normal: int = 12, outliers: int = 3) -> None:
    for i in range(n_normal):
        insert_event(job_id, ts=f"2026-08-25T10:{i:02d}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                     src_port=40000 + i, status="failed", severity="MEDIUM",
                     message=f"Failed password for admin from 185.23.45.67 attempt {i}")
    for i in range(outliers):
        insert_event(job_id, ts=f"2026-08-25T10:{50 + i}:02Z", event_type="auth_failure",
                     src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=6666,
                     src_port=50000 + i, status="denied", severity="CRITICAL",
                     message=f"{'X' * 400} shock event {i}")


def test_retrain_is_deterministic():
    _seed_job("ml_det_a")
    sa = mlm.train_job("ml_det_a")
    _seed_job("ml_det_b")
    sb = mlm.train_job("ml_det_b")
    assert sa["trained"] and sb["trained"]
    assert sa["n_anomalies"] == sb["n_anomalies"] > 0, "identical input, identical tags"
    with db() as conn:
        a = [r["anomaly_score"] for r in conn.execute(
            "SELECT anomaly_score FROM events WHERE job_id='ml_det_a' ORDER BY id")]
        b = [r["anomaly_score"] for r in conn.execute(
            "SELECT anomaly_score FROM events WHERE job_id='ml_det_b' ORDER BY id")]
    assert a == b


def test_outlier_events_get_flagged():
    _seed_job("ml_flag")
    stats = mlm.train_job("ml_flag")
    assert stats["trained"]
    assert stats["n_anomalies"] >= 1
    with db() as conn:
        top = [dict(r) for r in conn.execute(
            "SELECT id, message, anomaly_score FROM events WHERE job_id='ml_flag'"
            " ORDER BY anomaly_score DESC LIMIT 3")]
    assert top[0]["anomaly_score"] >= 0.7
    flagged = [r for r in top if "shock event" in (r["message"] or "")]
    assert flagged, "the shock events must rank among the most anomalous"


def test_tiny_job_is_skipped_gracefully():
    insert_event("ml_tiny", ts="2026-08-25T10:00:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                 status="failed", message="Failed password")
    insert_event("ml_tiny", ts="2026-08-25T10:01:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                 status="failed", message="Failed password")
    insert_event("ml_tiny", ts="2026-08-25T10:02:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=23,
                 status="failed", message="Failed password")
    stats = mlm.train_job("ml_tiny")
    assert stats["trained"] is False
    assert stats["n_anomalies"] == 0


def test_anomaly_bump_flows_into_detection_reasons():
    job = "ml_pipe"
    for i in range(7):
        insert_event(job, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="198.51.100.4", dst_ip="10.0.0.15", dst_port=22,
                     src_port=40000 + i, status="failed", severity="MEDIUM",
                     message=f"Failed password for root from 198.51.100.4 attempt {i}")
    insert_event(job, ts="2026-08-25T10:06:00Z", event_type="auth_failure",
                 src_ip="198.51.100.4", dst_ip="10.0.0.15", dst_port=6666,
                 src_port=50000, status="denied", severity="CRITICAL",
                 message=f"{'Y' * 400} shock event")
    assert evaluate_job(job), "brute-force rule must fire"
    stats = mlm.train_job(job)
    assert stats["trained"] and stats["n_anomalies"] >= 1
    build_incidents(job)
    with db() as conn:
        rows = conn.execute(
            "SELECT reasons_json FROM detections WHERE job_id = ?", (job,)).fetchall()
    reasons: list[str] = []
    for r in rows:
        reasons.extend(json.loads(r["reasons_json"] or "[]"))
    assert any("ML anomaly signal" in x for x in reasons), reasons


def test_ml_endpoint_reports_model_and_anomalies():
    job_id = jobs.create_job("ml_api_job.log", 0, source_type="upload")
    _seed_job(job_id)
    mlm.train_job(job_id)
    payload = ml_job(job_id)
    assert payload["trained"] is True
    assert payload["model"]["features"] == mlm.FEATURE_NAMES
    assert payload["summary"]["n_events"] >= 1
    assert payload["summary"]["n_anomalies"] >= 1
    assert payload["anomalies"], "top anomalous events expected"
    assert payload["anomalies"][0]["anomaly_score"] >= 0.5