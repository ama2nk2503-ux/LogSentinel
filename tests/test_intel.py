import json

from core.storage import db
from intelligence.aggregator import _recommendation, build_intel
from tests.test_detection import insert_event


def _seed_with_ioc(job):
    insert_event(job, ts="2026-08-25T18:00:01Z", event_type="auth_failure",
                 src_ip="185.23.45.67", username="admin", status="failure",
                 message="Failed password for admin from 185.23.45.67")
    insert_event(job, ts="2026-08-25T18:00:02Z", event_type="auth_failure",
                 src_ip="185.23.45.67", username="admin", status="failure",
                 message="Failed password for admin from 185.23.45.67")
    insert_event(job, ts="2026-08-25T18:00:03Z", event_type="auth_failure",
                 src_ip="185.23.45.67", username="admin", status="failure",
                 message="Failed password for admin from 185.23.45.67 hash deadbeef" * 0 +
                         " md5 5d41402abc4b2a76b9719d911017c592")


def test_indicator_aggregation_fields():
    job = "t_intel1"
    _seed_with_ioc(job)
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    evaluate_job(job)
    build_incidents(job)
    # IOCs are extracted at ingest normally; emulate stored iocs_json here:
    with db() as conn:
        conn.execute(
            "UPDATE events SET iocs_json = ? WHERE job_id = ? AND src_ip = '185.23.45.67'",
            (json.dumps([{"value": "185.23.45.67", "type": "ipv4",
                          "confidence": 0.99, "private": False}]), job))
        conn.execute(
            "UPDATE events SET threat_type = 'Brute Force' WHERE job_id = ?", (job,))

    intel = build_intel(job)
    vals = {i["value"]: i for i in intel["indicators"]}
    assert "185.23.45.67" in vals
    ind = vals["185.23.45.67"]
    assert ind["type"] == "ipv4"
    assert ind["related_events"] == 3
    assert ind["first_seen"] <= ind["last_seen"]
    assert ind["confidence"] >= 0.9
    assert "brute" in ind["threat_type"].lower() or ind["threat_type"]


def test_report_structure_and_recommendation():
    job = "t_intel2"
    _seed_with_ioc(job)
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    evaluate_job(job)
    incidents = build_incidents(job)
    assert incidents
    intel = build_intel(job)
    rep = intel["reports"][0]
    for field in ("title", "threat", "source", "events", "severity",
                  "classification", "risk_score", "confidence", "evidence",
                  "why", "recommended_response"):
        assert field in rep, f"missing {field}"
    assert len(rep["evidence"]) >= 1
    assert rep["recommended_response"] and rep["recommended_response"].endswith(".")
    assert all(w.startswith("+") for w in rep["why"])


def test_recommendation_mapping():
    assert "MFA" in _recommendation("Brute Force")
    assert "WAF" in _recommendation("Web Attack")
    assert "Isolate" in _recommendation("Malware")
    assert _recommendation("Totally New Category").endswith(".")


def test_indicator_upsert_idempotent():
    job = "t_intel3"
    _seed_with_ioc(job)
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    evaluate_job(job)
    build_incidents(job)
    with db() as conn:
        conn.execute(
            "UPDATE events SET iocs_json = ? WHERE job_id=?",
            (json.dumps([{"value": "5d41402abc4b2a76b9719d911017c592",
                          "type": "md5", "confidence": 0.99}]), job))
    build_intel(job)
    first_count = build_intel(job)
    with db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) c FROM indicators WHERE type='md5'").fetchone()["c"]
    assert n == 1  # upsert, not duplicate
