"""CERT-In (India) compliance framework tests (M5 Item 4)."""

from core import compliance
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from tests.test_detection import insert_event


def _certin(job) -> dict:
    result = next((r for r in compliance.audit_job(job) if r["framework"] == "CERT-In (India)"), None)
    assert result is not None, "CERT-In (India) framework must be registered and evaluated"
    return result


def test_certin_registered_as_fifth_framework():
    names = [f["name"] for f in compliance.list_frameworks()]
    assert "CERT-In (India)" in names
    # Same evaluation mechanism as the existing four: severity -> status.
    certin = next(f for f in compliance.list_frameworks() if f["name"] == "CERT-In (India)")
    for control in certin["controls"]:
        assert control["metric"] in (
            "event_count", "detection_count", "incident_count",
            "untriaged_incidents", "pii_count", "risk_surface")
        assert control["severity"] in ("critical", "high", "medium", "low")


def test_clean_job_passes_logging_ntp_and_retention():
    job = "certin_clean"
    for i in range(4):
        insert_event(job, ts=f"2026-08-26T10:0{i}:00Z", event_type="http_request",
                     src_ip="198.51.100.33", timestamp_source="event",
                     message=f"GET /api/health {i}")
    result = _certin(job)
    by = {f["control"]: f["status"] for f in result["findings"]}
    assert by["CERT-LOG-01"] == "PASS", "logged events prove mandatory logging"
    assert by["CERT-NTP-01"] == "PASS", "native event timestamps feed the NTP proxy"
    assert by["CERT-RET-01"] == "PASS", "audit trail present over the reviewed window"
    assert result["score"] >= 60


def test_bruteforce_job_flags_hygiene_and_reporting_lag():
    job = "certin_bad"
    # A concentrated login-storm (8 failures on one user/IP) must trip the
    # credential-hygiene control — beyond the 5-per-window limit — and the
    # resulting untriaged incident must break the reporting cadence.
    for i in range(8):
        insert_event(job, ts=f"2026-08-26T10:{i:02d}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.99", username="admin", status="failure",
                     message=f"Failed password for admin from 185.23.45.99 #{i}")
    insert_event(job, ts="2026-08-26T10:10:00Z", event_type="auth_success",
                 src_ip="185.23.45.99", username="admin", status="success",
                 message="Accepted password for admin from 185.23.45.99")
    evaluate_job(job)
    build_incidents(job)
    result = _certin(job)
    by = {f["control"]: f["status"] for f in result["findings"]}
    # Credential-safety hygiene must flag on concentrated auth failures.
    assert by["CERT-HYG-01"] in ("WARN", "FAIL")
    # Incidents awaiting analyst triage break the reporting-timeline control.
    assert by["CERT-RPT-01"] == "FAIL"
    assert by["CERT-LOG-01"] == "PASS", "logging is present regardless of posture"
    # A reporting failure must surface as a framework FAIL, not a silent pass.
    assert any(by[c] != "PASS" for c in by)


def test_certin_history_persists_and_report_renders():
    _certin("certin_clean")
    rows = compliance.audit_history("certin_clean")
    certin = next((r for r in rows if r["framework"] == "CERT-In (India)"), None)
    assert certin is not None
    assert "passed" in certin["summary"] and certin["findings"]
    md = compliance.render_report("certin_clean", "cert-in (india)")
    assert "# LogSentinel Compliance Report" in md
    assert "CERT-In (India)" in md
    with db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM audits WHERE framework = 'CERT-In (India)'"
                         " AND job_id = 'certin_clean'").fetchone()["c"]
    assert n >= 1