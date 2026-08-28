from core.storage import db
from core.timeline import build_timeline
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from tests.test_correlation import _seed_bruteforce_chain


def _incident_id(job: str) -> int:
    evaluate_job(job)
    incidents = build_incidents(job)
    assert incidents
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM correlations WHERE job_id = ? ORDER BY id LIMIT 1",
            (job,)).fetchone()
    return row["id"]


def test_timeline_phase_cluster():
    job = "tm_chain"
    _seed_bruteforce_chain(job)
    inc_id = _incident_id(job)

    tl = build_timeline(inc_id)
    assert tl["incident_id"] == inc_id
    phases = tl["phases"]
    assert phases, "expected phase-clustered timeline"
    tactics = [p["tactic"] for p in phases]
    # brute force maps to credential-access; sudo/command maps to execution/privesc
    assert "credential-access" in tactics
    assert any(t in ("privilege-escalation", "execution") for t in tactics)
    # tactic order follows attack_mapping's declared progression
    order = tl["tactics_order"]
    idx = [order.index(t) if t in order else -1 for t in tactics]
    assert idx == sorted(idx) and -1 not in idx
    total_entries = sum(p["count"] for p in phases)
    assert total_entries >= 4
    assert all(p["start"] and p["end"] for p in phases if p["count"])


def test_timeline_unknown_incident():
    assert build_timeline(999999) is None


def test_timeline_maps_unmapped_rules():
    job = "tm_clean"
    with db() as conn:
        conn.execute(
            "INSERT INTO correlations (job_id, title, category, classification,"
            " severity, entity, risk_score, timeline_json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (job, "Mystery", "Unknown", "SUSPICIOUS", "LOW", "10.0.0.9", 12, '[]'))
        row = conn.execute(
            "SELECT id FROM correlations WHERE job_id = ? LIMIT 1", (job,)).fetchone()
    tl = build_timeline(row["id"])
    assert tl["phases"] == []