"""Shared local-LLM bridge — auto-on, tiny-model light, options + timeout."""

import json

import pytest

from ai import llm


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("LOGSENTINEL_AI_SUMMARY", "LOGSENTINEL_LLM_URL",
                "LOGSENTINEL_LLM_MODEL", "LOGSENTINEL_LLM_TIMEOUT_S"):
        monkeypatch.delenv(var, raising=False)
    yield
    llm.clear_persisted_ai_mode()


def test_mode_defaults_to_auto_and_switch_is_on():
    assert llm.mode() == "auto"
    assert llm.switch_on() is True


def test_persisted_mode_roundtrip():
    assert llm.get_persisted_ai_mode() is None
    assert llm.mode() == "auto"
    llm.set_persisted_ai_mode("off")
    assert llm.get_persisted_ai_mode() == "off"
    assert llm.mode() == "off"
    assert llm.switch_on() is False
    llm.set_persisted_ai_mode("on")
    assert llm.mode() == "on"
    assert llm.switch_on() is True


def test_env_override_beats_persisted_mode(monkeypatch):
    llm.set_persisted_ai_mode("on")
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "off")
    assert llm.mode() == "off"
    assert llm.switch_on() is False
    monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", "1")
    assert llm.mode() == "on"
    assert llm.switch_on() is True


def test_mode_values(monkeypatch):
    for v in ("1", "true", "on", "yes"):
        monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", v)
        assert llm.mode() == "on"
        assert llm.switch_on() is True
    for v in ("0", "false", "off", "no"):
        monkeypatch.setenv("LOGSENTINEL_AI_SUMMARY", v)
        assert llm.mode() == "off"
        assert llm.switch_on() is False


def test_probe_false_when_endpoint_down(monkeypatch):
    monkeypatch.setattr(llm, "_probe", lambda base: None)
    assert llm.probe() is False


def test_probe_true_when_endpoint_answers(monkeypatch):
    monkeypatch.setattr(llm, "_probe", lambda base: {"models": []})
    assert llm.probe() is True


def test_pick_configured_model(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_LLM_MODEL", "custom:latest")
    assert llm.llm_model() == "custom:latest"


def test_pick_prefers_tiny_default(monkeypatch):
    monkeypatch.setattr(llm, "_installed_models",
                        lambda: ["llama3.2:1b", "qwen2.5:0.5b", "llama3"])
    assert llm.llm_model() == "qwen2.5:0.5b"


def test_pick_lightest_installed(monkeypatch):
    monkeypatch.setattr(llm, "_installed_models", lambda: ["llama3", "llama3.2:1b"])
    assert llm.llm_model() == "llama3.2:1b"


def test_pick_default_when_none_installed(monkeypatch):
    monkeypatch.setattr(llm, "_installed_models", lambda: [])
    assert llm.llm_model() == llm.DEFAULT_MODEL == "qwen2.5:0.5b"


def test_generate_sends_light_options_and_long_timeout(monkeypatch):
    captured = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        @staticmethod
        def read():
            return b'{"response": "straight answer"}'

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data)
        captured["timeout"] = timeout
        return Resp()

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(llm, "llm_url", lambda: "http://127.0.0.1:11434")
    monkeypatch.setenv("LOGSENTINEL_LLM_MODEL", "qwen2.5:0.5b")
    assert llm.generate("hi", max_tokens=120) == "straight answer"

    body = captured["body"]
    assert body["model"] == "qwen2.5:0.5b"
    assert body["stream"] is False
    assert body["options"] == {
        "num_predict": 120, "temperature": 0.2, "num_ctx": 2048}
    assert body["keep_alive"] == "720h"
    assert captured["timeout"] == llm.llm_timeout()
    assert captured["timeout"] > 30


def test_generate_keep_alive_override(monkeypatch):
    monkeypatch.setattr(llm, "llm_url", lambda: "http://127.0.0.1:11434")
    assert llm.llm_keep_alive() == llm._KEEP_ALIVE == "720h"
    assert llm.llm_keep_alive() == llm.llm_keep_alive()  # normalized "-1"
    monkeypatch.setenv("LOGSENTINEL_LLM_KEEP_ALIVE", "5m")
    assert llm.llm_keep_alive() == "5m"
    monkeypatch.setenv("LOGSENTINEL_LLM_KEEP_ALIVE", "-1")
    assert llm.llm_keep_alive() == llm._KEEP_ALIVE == "720h"
    monkeypatch.setenv("LOGSENTINEL_LLM_KEEP_ALIVE", " ")
    assert llm.llm_keep_alive() == "720h"


def test_warmup_preloads_when_model_present(monkeypatch):
    calls = []

    def fake_generate(prompt, max_tokens):
        calls.append((prompt, max_tokens))
        return "ok"

    monkeypatch.setattr(llm, "probe", lambda: True)
    monkeypatch.setattr(llm, "generate", fake_generate)
    assert llm.warmup(block=True) is True
    assert len(calls) == 1
    assert calls[0][1] == 8


def test_warmup_noop_when_no_model(monkeypatch):
    monkeypatch.setattr(llm, "probe", lambda: False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("generate must not run without a model")

    monkeypatch.setattr(llm, "generate", fail_if_called)
    assert llm.warmup(block=True) is False


def test_generate_timeout_override(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_LLM_TIMEOUT_S", "12")
    assert llm.llm_timeout() == 12.0
    monkeypatch.setenv("LOGSENTINEL_LLM_TIMEOUT_S", "garbage")
    assert llm.llm_timeout() == llm._GEN_TIMEOUT_S


def test_generate_num_gpu_override(monkeypatch):
    captured = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        @staticmethod
        def read():
            return b'{"response": "cpu answer"}'

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data)
        return Resp()

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(llm, "llm_url", lambda: "http://127.0.0.1:11434")
    monkeypatch.setenv("LOGSENTINEL_LLM_MODEL", "qwen2.5:0.5b")

    assert llm.generate("hi", max_tokens=50) == "cpu answer"
    assert "num_gpu" not in captured["body"]["options"]

    monkeypatch.setenv("LOGSENTINEL_LLM_NUM_GPU", "0")
    assert llm.generate("hi", max_tokens=50) == "cpu answer"
    assert captured["body"]["options"]["num_gpu"] == 0

    monkeypatch.setenv("LOGSENTINEL_LLM_NUM_GPU", "garbage")
    assert llm.generate("hi", max_tokens=50) == "cpu answer"
    assert "num_gpu" not in captured["body"]["options"]


def test_generate_never_raises_on_llm_absence(monkeypatch):
    def _boom(req, timeout=None):
        raise RuntimeError("endpoint down")

    monkeypatch.setattr(llm.urllib.request, "urlopen", _boom)
    monkeypatch.setattr(llm, "llm_url", lambda: "http://127.0.0.1:11434")
    monkeypatch.setenv("LOGSENTINEL_LLM_MODEL", "qwen2.5:0.5b")
    assert llm.generate("hi", max_tokens=50) is None