import json

import pytest

from core.storage import db
from core import triage


def _incident(job: str, *, risk: int = 60, title: str = "Test Incident") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO correlations (job_id, title, category, classification,"
            " severity, entity, risk_score, reasons_json, evidence_event_ids_json,"
            " timeline_json, techniques_json, killchain_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (job, title, "Brute Force", "MALICIOUS", "HIGH", "185.23.45.67", risk,
             '[]', '[]', '[]', '[]', '{}'))
        return cur.lastrowid


def test_status_lifecycle():
    inc_id = _incident("t_inc1")
    updated = triage.set_status(inc_id, "ACKNOWLEDGED")
    assert updated["status"] == "ACKNOWLEDGED"
    assert updated["acknowledged_at"]

    updated = triage.set_status(inc_id, "IN_PROGRESS")
    assert updated["status"] == "IN_PROGRESS"

    updated = triage.set_status(inc_id, "ESCALATED")
    assert updated["status"] == "ESCALATED"

    updated = triage.set_status(inc_id, "RESOLVED")
    assert updated["status"] == "RESOLVED"
    assert updated["resolved_at"]


def test_invalid_status_rejected():
    inc_id = _incident("t_inc2")
    with pytest.raises(ValueError):
        triage.set_status(inc_id, "BANANAS")


def test_assign_and_notes():
    inc_id = _incident("t_inc3")
    triage.assign(inc_id, "analyst.eve")
    triage.add_note(inc_id, "Quarantined host; contact owner.")
    updated = triage.add_note(inc_id, "Second note.")
    assert updated["assignee"] == "analyst.eve"
    notes = json.loads(updated["notes_json"])
    assert len(notes) == 2
    assert notes[0]["note"].startswith("Quarantined")

    with pytest.raises(ValueError):
        triage.add_note(inc_id, "   ")


def test_false_positive_feedback():
    inc_id = _incident("t_inc4", risk=80)
    updated = triage.set_status(inc_id, "FALSE_POSITIVE")
    assert updated["false_positive"] == 1
    assert updated["risk_score"] <= 40
    reasons = json.loads(updated["reasons_json"])
    assert any("false-positive" in r for r in reasons)


def test_missing_incident_returns_none():
    assert triage.set_status(999999, "RESOLVED") is None
    assert triage.add_note(999999, "nope") is None
    assert triage.assign(999999, "nobody") is None


def test_summary_counts():
    _incident("t_inc5", risk=70)
    _incident("t_inc6", risk=30)
    s = triage.summary()
    assert s["open"] >= 1
    assert s["counts"].get("NEW", 0) >= 1