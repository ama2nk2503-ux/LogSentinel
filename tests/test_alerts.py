import pytest

from core import alerts
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from detection.attack import enrich_job
from tests.test_correlation import _seed_bruteforce_chain
from tests.test_detection import insert_event


@pytest.fixture(scope="module", autouse=True)
def ensure_alert_rules():
    assert alerts.reload_alert_rules() >= 5, "alert seed rules must load"
    return True


def _run(job):
    evaluate_job(job)
    build_incidents(job)
    enrich_job(job)
    return alerts.evaluate_alerts(job)


def test_brute_force_produces_alert():
    job = "a_bf"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T09:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     message=f"Failed password for admin #{i}")
    created = _run(job)
    bf = [a for a in created if a["alert_rule_id"] == "ALERT_BRUTE_FORCE"]
    assert len(bf) == 1
    assert bf[0]["entity"] == "185.23.45.67"
    assert bf[0]["status"] == "OPEN"
    assert bf[0]["severity"] == "HIGH"
    assert len(alerts.list_alerts()) >= 1


def test_dedup_suppresses_repeat_evaluation():
    job = "a_dedup"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="198.51.100.9", username="root", status="failure",
                     message=f"Failed #{i}")
    first = _run(job)
    second = alerts.evaluate_alerts(job)
    assert len(first) >= 1
    assert second == []


def test_incident_alert_risk_gate():
    job = "a_inc"
    _seed_bruteforce_chain(job)
    created = _run(job)
    inc_alerts = [a for a in created
                  if a["alert_rule_id"] in ("ALERT_CRITICAL_INCIDENT", "ALERT_HIGH_INCIDENT")]
    assert inc_alerts, f"expected risk-gated incident alerts, got {[a['alert_rule_id'] for a in created]}"
    assert inc_alerts[0]["risk_score"] >= 51


def test_ioc_alert_on_high_confidence():
    job = "a_ioc"
    with db() as conn:
        conn.execute(
            "INSERT INTO indicators (value, type, threat_type, severity, confidence,"
            " first_seen, last_seen, related_events)"
            " VALUES (?,?,?,?,?,?,?,?)",
            ("danger.example.invalid", "domain", "C2", "HIGH", 0.97,
             "2026-08-25T00:00:00Z", "2026-08-25T00:01:00Z", 3))
    created = alerts.evaluate_alerts(job)
    ioc = [a for a in created if a["alert_rule_id"] == "ALERT_HIGH_CONF_IOC"]
    assert len(ioc) == 1
    assert ioc[0]["entity"] == "danger.example.invalid"


def test_alert_workflow_transitions():
    job = "a_wf"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T11:0{i}:00Z", event_type="auth_failure",
                     src_ip="192.0.2.44", username="admin", status="failure",
                     message=f"Failed #{i}")
    created = _run(job)
    bf = [a for a in created if a["alert_rule_id"] == "ALERT_BRUTE_FORCE"][0]
    alert_id = bf["id"]

    acked = alerts.ack(alert_id)
    assert acked["status"] == "ACKNOWLEDGED"
    assert acked["acknowledged_at"]

    assert alerts.get_alert(alert_id) is not None

    resolved = alerts.resolve(alert_id)
    assert resolved["status"] == "RESOLVED"
    assert resolved["resolved_at"]
    assert resolved["acknowledged_at"]


def test_false_positive_feedback_downgrades_incident():
    job = "a_fp"
    _seed_bruteforce_chain(job)
    created = _run(job)
    inc_alerts = [a for a in created
                  if a["alert_rule_id"] in ("ALERT_CRITICAL_INCIDENT", "ALERT_HIGH_INCIDENT")]
    assert inc_alerts
    alert = inc_alerts[0]
    meta = alert.get("metadata") or {}
    inc_id = meta.get("incident_id")
    assert inc_id, "incident alert metadata must carry incident_id"

    with db() as conn:
        before = conn.execute(
            "SELECT risk_score FROM correlations WHERE id = ?", (inc_id,)).fetchone()

    fp = alerts.false_positive(alert["id"])
    assert fp["status"] == "FALSE_POSITIVE"

    with db() as conn:
        after = conn.execute(
            "SELECT risk_score, false_positive, status FROM correlations WHERE id = ?",
            (inc_id,)).fetchone()
    assert after["false_positive"] == 1
    assert after["status"] == "FALSE_POSITIVE"
    assert after["risk_score"] <= max(1, before["risk_score"] // 2)
    assert after["risk_score"] < before["risk_score"]


def test_rule_crud_and_reload():
    alerts.create_rule({"rule_id": "ALERT_TEST_ONLY", "name": "Test Alert",
                        "source_type": "detection", "severity": "LOW",
                        "threshold": 2})
    rules = {r["rule_id"]: r for r in alerts.list_alert_rules()}
    assert "ALERT_TEST_ONLY" in rules
    assert rules["ALERT_TEST_ONLY"]["threshold"] == 2

    updated = alerts.update_rule("ALERT_TEST_ONLY", {"threshold": 5, "enabled": False})
    assert updated["threshold"] == 5 and updated["enabled"] == 0

    count_after_reload = alerts.reload_alert_rules()
    rules = {r["rule_id"]: r for r in alerts.list_alert_rules()}
    assert "ALERT_TEST_ONLY" not in rules
    assert count_after_reload >= 5

    with pytest.raises(ValueError):
        alerts.create_rule({"rule_id": "ALERT_BRUTE_FORCE", "name": "dup"})


def test_notify_without_channels_reports_not_delivered():
    job = "a_notify"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T12:0{i}:00Z", event_type="auth_failure",
                     src_ip="203.0.113.7", username="admin", status="failure",
                     message=f"Failed #{i}")
    created = _run(job)
    bf = [a for a in created if a["alert_rule_id"] == "ALERT_BRUTE_FORCE"][0]
    result = alerts.post_notify(bf["id"])
    assert result["delivered"] is False
    assert "no notifier configured" in result["reason"]