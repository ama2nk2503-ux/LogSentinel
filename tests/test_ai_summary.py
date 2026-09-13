"""M4 item 10: optional AI narration — auto-on, light, honest."""

import pytest

from ai import llm as ai_llm
import ai.summary as ais
from ai.summary import DISCLAIMER, enabled, narrate_risk


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("LOGSENTINEL_AI_SUMMARY", raising=False)
    monkeypatch.delenv("LOGSENTINEL_LLM_URL", raising=False)
    monkeypatch.delenv("LOGSENTINEL_LLM_MODEL", raising=False)
    monkeypatch.setattr(ai_llm, "probe", lambda: False)
    yield
    ai_llm.clear_persisted_ai_mode()


def test_forced_off_never_dials_and_returns_none(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "0")
    def _boom():  # pragma: no cover - must never be reached
        raise AssertionError("availability probe must not run while off")
    monkeypatch.setattr(ai_llm, "probe", _boom)
    assert enabled() is False
    assert narrate_risk("brute force", 80, ["+30 severity HIGH"]) is None


def test_auto_without_model_uses_deterministic_template():
    assert enabled() is True
    out = narrate_risk("SSH brute force", 80,
                       ["+30 severity HIGH", "+20 ML anomaly signal"])
    assert out is not None
    assert out["source"] == "deterministic_template"
    assert out["disclaimer"] == DISCLAIMER
    assert "80/100" in out["narration"]
    assert "+30 severity HIGH" in out["narration"]


def test_on_without_local_llm_uses_deterministic_template(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    out = narrate_risk("SSH brute force", 80,
                       ["+30 severity HIGH", "+20 ML anomaly signal"])
    assert out is not None
    assert out["source"] == "deterministic_template"
    assert out["disclaimer"] == DISCLAIMER
    assert "80/100" in out["narration"]
    assert "+30 severity HIGH" in out["narration"]


def test_auto_with_local_llm_narrates(monkeypatch):
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm",
                        lambda prompt: "Three failed logins escalated risk.")
    out = narrate_risk("SSH brute force", 80, ["+30 severity HIGH"])
    assert out["source"] == "local_llm"
    assert out["narration"] == "Three failed logins escalated risk."
    assert out["disclaimer"] == DISCLAIMER


def test_on_with_local_llm_narrates(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm",
                        lambda prompt: "Three failed logins escalated risk.")
    out = narrate_risk("SSH brute force", 80, ["+30 severity HIGH"])
    assert out["source"] == "local_llm"
    assert out["narration"] == "Three failed logins escalated risk."
    assert out["disclaimer"] == DISCLAIMER


def test_llm_failure_falls_back_to_template(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm", lambda prompt: None)
    out = narrate_risk("Port scan", 55, ["+25 many ports touched"])
    assert out["source"] == "deterministic_template"


def test_empty_reasons_never_narrates(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    assert narrate_risk("clean", 10, []) is None


def test_disclaimer_wording_is_the_mandated_one():
    assert DISCLAIMER == "AI-generated summary — verify against evidence below."


def test_threats_payload_carries_narration(monkeypatch):
    from tests.test_detection import insert_event
    from api.routes_threats import job_threats
    from detection.engine import evaluate_job
    from detection.correlator import build_incidents
    from core import jobs

    job = jobs.create_job("ai_sum.log", 0)
    for i in range(8):
        insert_event(job, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", dst_ip="10.0.0.15", dst_port=22,
                     status="failed", severity="HIGH",
                     message=f"Failed password for admin attempt {i}")
    evaluate_job(job)
    build_incidents(job)

    payload = job_threats(job)
    for inc in payload["incidents"]:
        assert inc["ai_summary"]["disclaimer"] == DISCLAIMER
        assert inc["ai_summary"]["source"] == "deterministic_template"

    monkeypatch.setattr(ai_llm, "probe", lambda: True)
    monkeypatch.setattr(ais, "_call_local_llm", lambda prompt: "local narration.")
    payload = job_threats(job)
    assert any(inc.get("ai_summary", {}).get("source") == "local_llm"
               for inc in payload["incidents"])