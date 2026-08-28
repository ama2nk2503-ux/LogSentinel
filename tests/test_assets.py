import json

import pytest

from core import alerts, assets
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from detection.attack import enrich_job
from tests.test_detection import insert_event


@pytest.fixture(scope="module", autouse=True)
def rules_loaded():
    assert alerts.reload_alert_rules() >= 8, "asset-aware seed rules must exist"
    return True


def _run(job):
    evaluate_job(job)
    build_incidents(job)
    enrich_job(job)
    assets.build_assets(job)
    return alerts.evaluate_alerts(job)


def test_assets_derive_from_events():
    job = "as_basic"
    insert_event(job, ts="2026-08-25T17:00:00Z", event_type="http_request",
                 src_ip="203.0.113.9", dst_ip="10.0.0.15", dst_port=80,
                 message="GET /login HTTP/1.1")
    insert_event(job, ts="2026-08-25T17:01:00Z", event_type="firewall_event",
                 src_ip="198.51.100.7", dst_ip="10.0.0.15", dst_port=443,
                 status="allow", message="ALLOW 443")
    built = assets.build_assets(job)
    assert built, "assets expected"
    listed = assets.list_assets(job)
    assert len(listed) >= 3  # 203.0.113.9 (src), 198.51.100.7 (src), 10.0.0.15 (dst web)
    by_name = {a["name"]: a for a in listed}
    web = by_name.get("10.0.0.15")
    assert web, listed
    assert web["asset_type"] == "web"
    assert web["criticality"] in ("HIGH", "CRITICAL")
    assert "web" in web["tags"] or "exposed" in web["tags"]


def test_asset_of_returns_latest_by_id():
    job_old = "as_old"
    job_new = "as_new"
    insert_event(job_old, ts="2026-08-25T18:00:00Z", event_type="http_request",
                 src_ip="203.0.113.9", dst_ip="10.0.0.15", dst_port=443,
                 message="GET / HTTP/1.1")
    insert_event(job_new, ts="2026-08-25T19:00:00Z", event_type="http_request",
                 src_ip="192.0.2.5", dst_ip="10.0.0.15", dst_port=80, message="GET / HTTP/1.1")
    assets.build_assets(job_old)
    assets.build_assets(job_new)
    a = assets.asset_of("10.0.0.15")
    assert a is not None and a["asset_type"] == "web"


def test_detections_flow_into_asset_counts():
    job = "as_det"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T19:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     message=f"Failed {i}")
    evaluate_job(job)
    assets.build_assets(job)
    by_name = {a["name"]: a for a in assets.list_assets(job)}
    att = by_name.get("185.23.45.67")
    assert att is not None
    assert att["detections_count"] >= 1


def test_asset_web_attack_alert_gates_on_web_asset():
    job = "as_web"
    ports = [21, 22, 23, 25, 80, 443, 445, 8080]  # >=6 distinct denied ports -> PORT_SCAN_001
    for i, p in enumerate(ports):
        insert_event(job, ts=f"2026-08-25T20:0{i}:00Z", event_type="firewall_event",
                     src_ip="203.0.113.9", dst_ip="10.0.0.15", dst_port=p,
                     status="deny", action="deny", message=f"DENY port {p}")
    created = _run(job)
    web_alerts = [a for a in created if a["alert_rule_id"] == "ALERT_ASSET_WEB_ATTACK"]
    assert web_alerts, f"expected web-asset alert, got {[a['alert_rule_id'] for a in created]}"
    assert web_alerts[0]["risk_score"] >= 40
    assert web_alerts[0]["entity"], "alert must carry an entity"


def test_web_asset_alert_does_not_fire_without_web_asset():
    job = "as_noweb"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T21:0{i}:00Z", event_type="auth_failure",
                     src_ip="203.0.113.9", username="admin", status="failure",
                     message=f"Failed {i}")
    created = _run(job)
    web_alerts = [a for a in created if a["alert_rule_id"] == "ALERT_ASSET_WEB_ATTACK"]
    assert not web_alerts, f"no web asset in play, but fired: {[a['alert_rule_id'] for a in created]}"


def test_criticality_gating_rule_exposed_helpers():
    assert alerts._criticality_rank("LOW") == 1
    assert alerts._criticality_rank("CRITICAL") == 4
    assert alerts._criticality_rank("nonsense") == 0


def test_metrics_in_storage_columns():
    row = None
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(alert_rules)").fetchall()]
    assert "asset_type" in cols and "min_criticality" in cols