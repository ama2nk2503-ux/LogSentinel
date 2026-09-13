import json
import uuid

import pytest

from core.storage import db
from detection.engine import evaluate_job, load_rules

TS = "2026-08-25T10:3{0}:00Z"


def insert_event(job_id, **kw):
    row = (
        kw.get("event_id") or uuid.uuid4().hex, job_id, kw.get("line_no"), kw.get("ts"), kw.get("event_type"),
        kw.get("source"), kw.get("src_ip"), kw.get("dst_ip"),
        kw.get("src_port"), kw.get("dst_port"), kw.get("protocol"),
        kw.get("username"), kw.get("hostname"), kw.get("action"),
        kw.get("status"), kw.get("severity", "LOW"), kw.get("message", ""),
        "", 0, kw.get("dedup_event_id", ""), kw.get("timestamp_source", "ingest"),
        "[]", "[]", "{}", "[]", "{}",
    )
    with db() as conn:
        conn.execute(
            "INSERT INTO events (event_id, job_id, line_no, ts, event_type, source,"
            " src_ip, dst_ip, src_port, dst_port, protocol, username, hostname,"
            " action, status, severity, message, threat_type, risk_score,"
            " dedup_event_id, timestamp_source,"
            " iocs_json, pii_json, mappings_json, attack_json, extras_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )


@pytest.fixture(scope="module", autouse=True)
def ensure_rules():
    assert len(load_rules()) >= 10
    return True


def test_brute_force_rule_fires_with_success_followup():
    job = "t_bf"
    for i in range(4):
        insert_event(job, ts=TS.format(i), event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     message=f"Failed password {i}")
    insert_event(job, ts=TS.format(5), event_type="auth_success",
                 src_ip="185.23.45.67", username="admin", status="success",
                 message="Accepted password for admin")
    dets = evaluate_job(job)
    bf = [d for d in dets if d["rule_id"] == "BRUTE_FORCE_001"]
    assert len(bf) == 1
    d = bf[0]
    assert d["entity"] == "185.23.45.67"
    assert d["severity"] == "HIGH"
    assert any("successful authentication" in r.lower() for r in d["reasons_json"])
    evidence = json.loads(json.dumps(d["evidence_json"]))
    assert len(evidence) >= 3


def test_port_scan_rule_fires_on_distinct_ports():
    job = "t_ps"
    ports = [21, 22, 23, 80, 443, 445, 3389]
    for i, p in enumerate(ports):
        insert_event(job, ts=f"2026-08-25T11:0{i % 10}:00Z", event_type="firewall_event",
                     src_ip="198.51.100.7", dst_ip="10.0.0.15", dst_port=p,
                     status="deny", action="deny", message=f"DENY port {p}")
    dets = evaluate_job(job)
    ps = [d for d in dets if d["rule_id"] == "PORT_SCAN_001"]
    assert len(ps) == 1
    assert ps[0]["category"] == "Port Scanning"


def test_sqli_rule_fires_from_message_regex():
    job = "t_sqli"
    insert_event(job, ts="2026-08-25T12:00:01Z", event_type="http_request",
                 src_ip="203.0.113.9",
                 message="GET /products.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1")
    dets = evaluate_job(job)
    sqli = [d for d in dets if d["rule_id"] == "WEB_SQLI_001"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "HIGH"


def test_traversal_and_xss_fire():
    job = "t_web2"
    insert_event(job, ts="2026-08-25T12:05:01Z", event_type="http_request",
                 src_ip="203.0.113.20", message="GET /../../etc/passwd HTTP/1.1")
    insert_event(job, ts="2026-08-25T12:05:02Z", event_type="http_request",
                 src_ip="203.0.113.21", message="GET /q=<script>alert(1)</script> HTTP/1.1")
    dets = {(d["rule_id"], d["entity"]) for d in evaluate_job(job)}
    assert ("WEB_TRAVERSAL_001", "203.0.113.20") in dets
    assert ("WEB_XSS_001", "203.0.113.21") in dets


def test_powershell_malware_rule_critical():
    job = "t_psh"
    insert_event(job, ts="2026-08-25T13:00:00Z", event_type="windows_event",
                 event_id=4688, username="administrator", hostname="DC01",
                 message="powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==")
    dets = evaluate_job(job)
    psh = [d for d in dets if d["rule_id"] == "MAL_POWERSHELL_001"]
    assert len(psh) == 1
    assert psh[0]["severity"] == "CRITICAL"


def test_below_threshold_no_detection():
    job = "t_quiet"
    insert_event(job, ts=TS.format(1), event_type="auth_failure",
                 src_ip="10.9.9.9", status="failure", message="one failure only")
    insert_event(job, ts=TS.format(2), event_type="auth_failure",
                 src_ip="10.9.9.9", status="failure", message="two failure")
    dets = [d for d in evaluate_job(job) if d["rule_id"] == "BRUTE_FORCE_001"]
    assert dets == []


def test_idempotent_evaluation():
    job = "t_idem"
    for i in range(5):
        insert_event(job, ts=f"2026-08-25T14:0{i}:00Z", event_type="auth_failure",
                     src_ip="203.0.113.99", status="failure", message=f"f{i}")
    first = [d for d in evaluate_job(job) if d["rule_id"] == "BRUTE_FORCE_001"]
    second = [d for d in evaluate_job(job) if d["rule_id"] == "BRUTE_FORCE_001"]
    assert len(first) == 1 and len(second) == 0
