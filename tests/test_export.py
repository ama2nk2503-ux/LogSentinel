import json

import pytest

from exporters.exporters import (export_cef, export_csv, export_json,
                                 export_leef, export_stix, export_syslog,
                                 _cef_escape_ext, _leef_escape)
from exporters.validator import (ExportValidationError, validate_cef,
                                 validate_csv, validate_export,
                                 validate_json, validate_leef,
                                 validate_stix, validate_syslog)
from privacy.policy_engine import save_policy
from tests.test_detection import insert_event


@pytest.fixture(scope="module", autouse=True)
def seeded(job_module_cleanup):
    job = "t_exp"
    with db_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO jobs (id, filename, size_bytes) VALUES (?, ?, ?)",
            (job, "export_test.log", 100))
    insert_event(job, ts="2026-08-25T19:00:00Z", event_type="auth_failure",
                 src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                 protocol="tcp", username="admin", hostname="srv1",
                 action="failed", status="failure", severity="HIGH",
                 message="contact amaan@example.com failed from 185.23.45.67")
    insert_event(job, event_id="fixed-id-2", ts="2026-08-25T19:01:00Z",
                 event_type="windows_event", username="administrator",
                 hostname="DC01", severity="CRITICAL",
                 message="powershell -enc AAAA password=TopSecret123")
    with db_conn() as conn:
        conn.execute(
            "UPDATE events SET iocs_json = ? WHERE job_id='t_exp' AND src_ip IS NOT NULL",
            (json.dumps([{"value": "185.23.45.67", "type": "ipv4",
                          "confidence": 0.99}]),))
    save_policy({"EMAIL": "REDACT"})
    yield job


@pytest.fixture(scope="module")
def job_module_cleanup():
    yield
    # nothing to tear down — isolated session DB


def db_conn():
    from core.storage import db
    return db()


# ---------- escaping helpers ----------

def test_cef_extension_escaping():
    out = _cef_escape_ext("evil=1|x\ny\\z")
    assert "\\=" in out and "\\|" in out and "\\n" in out
    assert "\n" not in out and "|" not in out.replace("\\|", "")


def test_leef_tab_escaping():
    assert "\t" not in _leef_escape("a\tb=c")


# ---------- exporters + validators ----------

def test_json_export_valid_and_policy_applied():
    payload = export_json("t_exp")
    validate_json(payload)
    obj = json.loads(payload)
    assert len(obj["events"]) == 2
    msgs = [e["message"] for e in obj["events"]]
    assert any("[EMAIL_REDACTED]" in m for m in msgs)
    assert not any("amaan@example.com" in m for m in msgs)
    assert all(e["redaction_status"] == "applied" for e in obj["events"])
    assert any(e["iocs"] for e in obj["events"])


def test_csv_export_structure():
    payload = export_csv("t_exp")
    validate_csv(payload)
    lines = payload.splitlines()
    assert lines[0].startswith("timestamp,event_id,event_type")
    assert len(lines) == 3


def test_cef_export_header_and_severity():
    payload = export_cef("t_exp")
    validate_cef(payload)
    first = payload.splitlines()[0]
    assert first.startswith("CEF:0|LogSentinel|ThreatProcessor|1.0|auth_failure|")
    assert "severity=8" in first          # HIGH -> 8
    assert "src=185.23.45.67" in first and "dpt=22" in first
    crit = payload.splitlines()[1]
    assert "severity=10" in crit


def test_leef_export_shape():
    payload = export_leef("t_exp")
    validate_leef(payload)
    line = payload.splitlines()[0]
    assert line.startswith("LEEF:1.0|LogSentinel|ThreatProcessor|1.0|auth_failure|")
    assert "usrName=admin" in line


def test_stix_bundle_indicators():
    payload = export_stix("t_exp")
    validate_stix(payload)
    bundle = json.loads(payload)
    assert bundle["type"] == "bundle"
    ind = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert ind and ind[0]["pattern_type"] == "stix"
    assert "[ipv4-addr:value = '185.23.45.67']" == ind[0]["pattern"]


def test_syslog_pri_present():
    payload = export_syslog("t_exp")
    validate_syslog(payload)
    first = payload.splitlines()[0]
    assert first.startswith("<35>")       # facility 4, HIGH->3 => 4*8+3
    assert "srv1" in first


# ---------- validator negative cases ----------

def test_validators_reject_garbage():
    for fmt, bad in [
        ("json", "{nope"),
        ("cef", "NOTCEF|broken"),
        ("leef", "LEEF:2.0 broken"),
        ("stix", "{\"type\": \"notbundle\"}"),
        ("syslog", "no pri here"),
        ("csv", ""),
    ]:
        with pytest.raises(ExportValidationError):
            validate_export(fmt, bad)


def test_unknown_format_rejected():
    with pytest.raises(ExportValidationError):
        validate_export("yaml42", "anything")
