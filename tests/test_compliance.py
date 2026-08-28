import json

import pytest

from core import compliance
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from tests.test_correlation import _seed_bruteforce_chain
from tests.test_detection import insert_event


@pytest.fixture(scope="module", autouse=True)
def frameworks_present():
    names = {f["name"] for f in compliance.list_frameworks()}
    assert names >= {"NIST SP 800-53", "ISO 27001:2022", "PCI-DSS v4.0", "CIS Controls v8"}
    return True


def _audit(job):
    return compliance.audit_job(job)


def test_benign_job_passes_monitoring_controls():
    job = "c_clean"
    for i in range(5):
        insert_event(job, ts=f"2026-08-25T15:0{i}:00Z", event_type="http_request",
                     src_ip="198.51.100.10", message=f"GET /index.html {i}")
    results = _audit(job)
    assert len(results) == 4
    by = {r["framework"]: {f["control"]: f["status"] for f in r["findings"]} for r in results}
    # Monitoring / hygiene controls must stay green on benign traffic.
    assert by["NIST SP 800-53"]["SI-4"] == "PASS"
    assert by["NIST SP 800-53"]["AU-6"] == "PASS"
    assert by["NIST SP 800-53"]["RA-5"] == "PASS"
    assert by["NIST SP 800-53"]["IR-4"] == "PASS"
    assert by["ISO 27001:2022"]["A.5.10"] == "PASS"
    assert by["PCI-DSS v4.0"]["REQ-10.2"] == "PASS"
    assert by["PCI-DSS v4.0"]["REQ-10.7"] == "PASS"
    # Boundary-protection controls intentionally demand deny evidence.
    assert by["NIST SP 800-53"]["SC-7"] == "FAIL"  # high severity -> FAIL
    assert by["CIS Controls v8"]["CIS-12.4"] != "PASS"  # medium -> WARN


def test_noncompliant_job_flags_failures():
    job = "c_bad"
    _seed_bruteforce_chain(job)
    evaluate_job(job)
    build_incidents(job)
    with db() as conn:
        conn.execute(
            "INSERT INTO events (event_id, job_id, line_no, ts, event_type, source,"
            " src_ip, dst_ip, src_port, dst_port, protocol, username, hostname,"
            " action, status, severity, message, threat_type, risk_score,"
            " iocs_json, pii_json, mappings_json, attack_json, extras_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("e_pii", job, 99, "2026-08-25T15:20:00Z", "http_request", "apache",
             "185.23.45.67", "10.0.0.15", 1234, 80, "tcp", "", "web0", "",
             "200", "LOW", "GET /login", "", 55, "[]", '["SSN"]', "{}", "[]", "{}"))
        conn.execute(
            "INSERT INTO events (event_id, job_id, ts, event_type, src_ip, message, risk_score)"
            " VALUES ('e_hi', ?, '2026-08-25T15:21:00Z', 'auth_failure', '198.51.100.20', 'x', 70)",
            (job,))
    results = _audit(job)
    assert any(r["status"] != "PASS" for r in results), results
    by = {f["control"]: f["status"] for r in results for f in r["findings"]}
    assert by["IR-4"] == "WARN", "untriaged incidents must flag IR-4"
    assert by["A.5.10"] == "WARN", "PII in logs must flag A.5.10"
    assert by["SC-7"] == "FAIL", "missing deny evidence must fail boundary protection"
    assert any(r["status"] == "FAIL" for r in results), results
    for r in results:
        assert r["findings"], "each framework must produce findings"


def test_audit_history_and_upsert():
    _audit("c_clean")
    rows = compliance.audit_history("c_clean")
    assert len(rows) == 4
    sts = {r["framework"] for r in rows}
    assert len(sts) == 4
    first = rows[0]
    assert "passed" in first["summary"]
    assert first["findings"]


def test_markdown_report_renders():
    _audit("c_bad")
    md = compliance.render_report("c_bad", "nist sp 800-53")
    assert md.startswith("# LogSentinel Compliance Report")
    assert "NIST SP 800-53" in md
    assert "## Findings" in md
    assert "| Control |" in md
    with pytest.raises(LookupError):
        compliance.render_report("c_bad", "NO_SUCH_FRAMEWORK")


def test_summarize_semantics():
    ok = compliance.summarize("F", [{"status": "PASS"}, {"status": "PASS"}])
    assert ok["status"] == "PASS" and ok["score"] == 100.0
    warn = compliance.summarize("F", [{"status": "PASS"}, {"status": "WARN"}])
    assert warn["status"] == "WARN"
    bad = compliance.summarize("F", [{"status": "FAIL"}, {"status": "WARN"}])
    assert bad["status"] == "FAIL"
    empty = compliance.summarize("F", [])
    assert empty["status"] == "NONE" and empty["score"] == 0.0


def test_filters_scoped_metric():
    job = "c_filt"
    insert_event(job, ts="2026-08-25T16:00:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", username="admin", status="failure",
                 message="Failed password")
    insert_event(job, ts="2026-08-25T16:01:00Z", event_type="http_request",
                 src_ip="198.51.100.11", message="GET /")
    total = compliance._metric_count(job, "event_count", {"event_type": "auth_failure"})
    assert total == 1