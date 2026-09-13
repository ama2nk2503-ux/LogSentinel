"""Standalone AI assistant chat — auto-on, deterministic facts, honest."""

import pytest

from ai import llm as ai_llm
import ai.assistant as ais
from ai.assistant import DISCLAIMER, assist, assistant_status


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("LOGSENTINEL_AI_SUMMARY", raising=False)
    monkeypatch.delenv("LOGSENTINEL_LLM_URL", raising=False)
    monkeypatch.delenv("LOGSENTINEL_LLM_MODEL", raising=False)
    monkeypatch.setattr(ai_llm, "probe", lambda: False)
    yield
    ai_llm.clear_persisted_ai_mode()


def _seed_job():
    from tests.test_detection import insert_event
    from core import jobs
    from detection.engine import evaluate_job
    from detection.correlator import build_incidents

    job = jobs.create_job("assistant_seed.log", 0)
    for i in range(8):
        insert_event(job, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                     status="failed", severity="HIGH",
                     message=f"Failed password for admin attempt {i}")
    jobs.merge_stats(job, total_lines=12, total_iocs=7, pii_events=2)
    evaluate_job(job)
    build_incidents(job)
    return job


def test_forced_off_status_never_dials(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "0")
    def _boom():  # pragma: no cover - must never be reached
        raise AssertionError("availability probe must not run while off")
    monkeypatch.setattr(ai_llm, "probe", _boom)
    st = assistant_status()
    assert st["mode"] == "off"
    assert st["enabled"] is False
    assert st["llm_available"] is False
    assert st["model"] is None
    assert st["model_hint"] is None


def test_persisted_off_status_never_dials(monkeypatch):
    ai_llm.set_persisted_ai_mode("off")
    def _boom():  # pragma: no cover - must never be reached
        raise AssertionError("availability probe must not run while off")
    monkeypatch.setattr(ai_llm, "probe", _boom)
    st = assistant_status()
    assert st["mode"] == "off"
    assert st["enabled"] is False
    assert st["llm_available"] is False
    assert st["model"] is None
    assert st["model_hint"] is None


def test_auto_without_model_status_is_deterministic():
    st = assistant_status()
    assert st["mode"] == "auto"
    assert st["enabled"] is True
    assert st["llm_available"] is False
    assert st["model"] is None
    assert st["model_hint"]


def test_auto_detects_model_and_switches_on(monkeypatch):
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ai_llm, "llm_model", lambda: "qwen2.5:0.5b")
    st = assistant_status()
    assert st["mode"] == "auto"
    assert st["llm_available"] is True
    assert st["model"] == "qwen2.5:0.5b"
    assert st["model_hint"] is None


def test_unknown_job_returns_none():
    assert assist("no-such-job", "what happened?", []) is None


def test_auto_without_model_returns_deterministic_answer_with_facts():
    job = _seed_job()
    out = assist(job, "which incidents were found?", [])
    assert out is not None
    assert out["source"] == "deterministic_template"
    assert out["disclaimer"] == DISCLAIMER
    assert out["question"] == "which incidents were found?"
    assert isinstance(out["facts"], list) and out["facts"]
    joined = "\n".join(out["facts"])
    assert "total_lines" not in joined  # facts are plain sentences


def test_facts_reflect_stored_data():
    job = _seed_job()
    out = assist(job, "what do we know?", [])
    joined = "\n".join(out["facts"])
    assert "assistant_seed.log" in joined
    assert "Total lines parsed: 12" in joined
    assert "Total IOCs extracted: 7" in joined


def test_enabled_without_local_llm_uses_deterministic_template(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    job = _seed_job()
    out = assist(job, "what happened?", [])
    assert out["source"] == "deterministic_template"
    assert out["disclaimer"] == DISCLAIMER


def test_enabled_with_fake_llm_narrates(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm",
                        lambda prompt: "Eight failed logins to admin from 185.23.45.67.")
    job = _seed_job()
    out = assist(job, "summarize the ssh failures", [])
    assert out["source"] == "local_llm"
    assert out["answer"] == "Eight failed logins to admin from 185.23.45.67."
    assert out["disclaimer"] == DISCLAIMER
    assert "assistant_seed.log" in "\n".join(out["facts"])


def test_llm_failure_falls_back_to_template(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm", lambda prompt: None)
    job = _seed_job()
    out = assist(job, "what happened?", [])
    assert out["source"] == "deterministic_template"


def test_llm_prompt_facts_are_capped_for_tiny_models(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    seen = {}
    def _fake_llm(prompt):
        seen["facts"] = prompt.count("- ")
        return "ok"
    monkeypatch.setattr(ais, "_call_local_llm", _fake_llm)
    big_facts = [f"fact number {i}" for i in range(80)]
    _ = ais._call_local_llm(ais._prompt("what?", [], big_facts[:ais._MAX_PROMPT_FACTS]))
    assert seen["facts"] == ais._MAX_PROMPT_FACTS


def test_history_is_capped_in_prompt():
    history = [{"role": "user", "content": f"m{i}"} for i in range(20)]
    facts = ["fact one", "fact two"]
    prompt = ais._prompt("what now?", history, facts)
    assert prompt.count("user: m") == ais._MAX_HISTORY_TURNS
    assert "fact one" in prompt and "Question: what now?" in prompt


def test_prompt_allows_grounded_mitigation_advice():
    prompt = ais._prompt("how do I fix it?", [],
                         ["Incident 'Brute Force Attack' … Remediation: block the source."])
    assert "mitigation advice" in prompt
    assert "never invent" in prompt
    assert "Remediation: block the source." in prompt


def test_fix_question_returns_remediation():
    job = _seed_job()
    out = assist(job, "how do I fix the brute force attack?", [])
    assert out["source"] == "deterministic_template"
    assert "Block source IP at the perimeter" in out["answer"]
    assert "Brute Force Attack" in out["answer"]
    assert out["disclaimer"] == DISCLAIMER


def test_error_question_returns_health_summary():
    job = _seed_job()
    out = assist(job, "what errors were found?", [])
    assert out["source"] == "deterministic_template"
    assert "failed/error" in out["answer"]
    assert "8 of 8" in out["answer"]


def test_evidence_question_returns_matching_events():
    job = _seed_job()
    out = assist(job, "show me the high-risk authentication events", [])
    assert out["source"] == "deterministic_template"
    assert "Found 8 matching events" in out["answer"]


def test_facts_include_remediation_and_evidence_lines():
    job = _seed_job()
    out = assist(job, "how do I fix the brute force attack?", [])
    joined = "\n".join(out["facts"])
    assert "Remediation: Block source IP at the perimeter" in joined

    out2 = assist(job, "show me the high-risk authentication events", [])
    joined2 = "\n".join(out2["facts"])
    assert "Evidence event" in joined2

    out3 = assist(job, "what do we know?", [])
    joined3 = "\n".join(out3["facts"])
    assert "Failed/error events: 8" in joined3
    assert "Total events recorded: 8" in joined3


def test_disclaimer_wording_is_the_mandated_one():
    assert DISCLAIMER == "AI-generated summary — verify against evidence below."


def test_status_field_names_are_backward_compatible():
    st = assistant_status()
    for key in ("enabled", "llm_available", "llm_url", "model"):
        assert key in st


def test_chat_route_roundtrip(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes_assistant import router

    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "0")
    job = _seed_job()
    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)
    r = client.post("/api/assistant", json={"job_id": job, "question": "what?", "history": []})
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "deterministic_template"
    assert body["disclaimer"] == DISCLAIMER

    r404 = client.post("/api/assistant", json={"job_id": "nope", "question": "what?", "history": []})
    assert r404.status_code == 404

    st = client.get("/api/assistant/status")
    assert st.status_code == 200
    assert st.json()["enabled"] is False


def test_patch_mode_route_roundtrip():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes_assistant import router

    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)

    assert client.get("/api/assistant/status").json()["enabled"] is True

    r = client.patch("/api/assistant/mode", json={"mode": "off"})
    assert r.status_code == 200
    st = r.json()
    assert st["mode"] == "off"
    assert st["enabled"] is False

    bad = client.patch("/api/assistant/mode", json={"mode": "banana"})
    assert bad.status_code == 422

    st = client.patch("/api/assistant/mode", json={"mode": "on"}).json()
    assert st["mode"] == "on"
    assert st["enabled"] is True