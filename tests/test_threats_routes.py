"""Routes /threats/{job_id} and /threats/{incident_id}/narration (lazy M4/M5).

The incidents list must stay fast and deterministic: recommended actions and
what-was-found narratives are computed inline under per-incident guards so a
single broken enrichment can never 500 the whole job view. AI narrations are
intentionally NOT on the list hot path — each card lazily fetches its own from
/narration, which is guarded the same way.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai import llm as ai_llm


@pytest.fixture(autouse=True)
def _hermetic_llm(monkeypatch):
    monkeypatch.delenv("LOGSENTINEL_AI_SUMMARY", raising=False)
    monkeypatch.delenv("LOGSENTINEL_LLM_URL", raising=False)
    monkeypatch.setattr(ai_llm, "probe", lambda: False)
    yield


def _seed_brute_force_job():
    from detection.correlator import build_incidents
    from detection.engine import evaluate_job
    from core import jobs
    from tests.test_detection import insert_event

    job = jobs.create_job("threat_routes.log", 0)
    for i in range(8):
        insert_event(job, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                     status="failed", severity="HIGH",
                     message=f"Failed password for admin attempt {i}")
    evaluate_job(job)
    build_incidents(job)
    return job


def _client():
    import api.routes_threats as rt

    app = FastAPI()
    app.include_router(rt.router, prefix="/api")
    return TestClient(app)


def _first_incident_id(job_id: int) -> int:
    from core.storage import db

    with db() as conn:
        return conn.execute(
            "SELECT id FROM correlations WHERE job_id = ? ORDER BY risk_score DESC LIMIT 1",
            (job_id,)).fetchone()[0]


def test_threats_job_payload_has_deterministic_fields_but_no_inline_narration():
    job = _seed_brute_force_job()
    r = _client().get(f"/api/threats/{job}")
    assert r.status_code == 200
    body = r.json()
    assert body["job_id"] == job
    assert body["incidents"], "expected seeded incidents"
    inc = body["incidents"][0]
    assert isinstance(inc["description"], dict)
    assert inc["description"]["provenance"]
    assert isinstance(inc["recommended_actions"], list)
    assert "ai_summary" not in inc  # lazy: narration belongs to the card fetch
    assert body["detections"]


def test_narration_endpoint_returns_deterministic_narration():
    job = _seed_brute_force_job()
    inc_id = _first_incident_id(job)
    r = _client().get(f"/api/threats/{inc_id}/narration")
    assert r.status_code == 200
    body = r.json()
    assert body["ai_summary"]["source"] == "deterministic_template"
    assert body["ai_summary"]["disclaimer"]
    assert "scored" in body["ai_summary"]["narration"]


def test_narration_endpoint_404_for_unknown_incident():
    assert _client().get("/api/threats/999999/narration").status_code == 404


def test_single_broken_enrichment_never_500s_the_job_view(monkeypatch):
    import api.routes_threats as rt

    job = _seed_brute_force_job()

    def _boom(*_a, **_k):
        raise RuntimeError("simulated enrichment failure")

    monkeypatch.setattr(rt, "describe_incident", _boom)
    monkeypatch.setattr(rt.soar, "recommended_actions", _boom)
    r = _client().get(f"/api/threats/{job}")
    assert r.status_code == 200
    inc = r.json()["incidents"][0]
    assert inc["description"] is None
    assert inc["recommended_actions"] == []


def test_broken_narration_returns_empty_body_not_500(monkeypatch):
    import ai.summary as ais

    job = _seed_brute_force_job()
    inc_id = _first_incident_id(job)

    def _boom(*_a, **_k):
        raise RuntimeError("simulated narration failure")

    monkeypatch.setattr(ais, "narrate_risk", _boom)
    assert _client().get(f"/api/threats/{inc_id}/narration").json() == {}