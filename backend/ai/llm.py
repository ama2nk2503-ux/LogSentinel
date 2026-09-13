"""Shared local-LLM bridge — auto-on and light enough for any machine.

Product decision: the old strict "off by default" gate is retired. The AI
engages automatically the moment a small local model answers at a localhost
endpoint you configure; when it is absent the app behaves deterministically
with no network call beyond a single localhost tags probe.

Semantics (env: LOGSENTINEL_AI_SUMMARY):
    "on"  / 1/true/yes -> forced on (still needs a reachable model)
    "off" / 0/false/no -> forced off; dials nothing
    unset/other        -> auto: on whenever a local model answers

The UI toggle writes the same 2-state preference (on = LLM attempt,
off = deterministic only) into the persisted `settings` table. An explicit
LOGSENTINEL_AI_SUMMARY env value always wins over the persisted setting so a
deployment can force a mode; otherwise the persisted value decides, and
unset both behaves as "auto".

Lightness guarantees (so a tiny model runs on a modest CPU/RAM machine):
    - probe timeout 2s; generation timeout 60s (LOGSENTINEL_LLM_TIMEOUT_S
      overridable). The old shared 2s timeout made CPU inference always
      fall back to deterministic — that is the bug this module fixes.
    - preferred model is the tiny ~0.5B qwen2.5:0.5b; otherwise the
      lightest installed model is auto-picked from /api/tags.
    - /api/generate carries num_predict + temperature 0.2 + num_ctx 2048
      so responses stay short, grounded and within small-model context.
- keep_alive defaults to "720h" (LOGSENTINEL_LLM_KEEP_ALIVE overridable):
      the tiny model stays resident in memory while the app runs, so warm
      answers skip reload + KV-build latency. Combined with warmup(), this
      keeps every chat response in the 2-5s band even right after a restart.
    - LOGSENTINEL_LLM_NUM_GPU (optional): force the GPU layer count sent to
      Ollama. "0" forces CPU-only inference — some machines degrade to
      garbage text on partial GPU offload, and CPU runs a 0.5B model fine.
      Unset lets Ollama decide.
    - warmup(): daemon-threaded one-shot preload at boot so the first user
      message is warm; no-op when no local model answers.
"""

import json
import os
import threading
import time
import urllib.request

from core.storage import db

DEFAULT_LLM_URL = "http://127.0.0.1:11434"  # Ollama-compatible, local only
DEFAULT_MODEL = "qwen2.5:0.5b"  # tiny 0.5B — runnable on modest hardware
_PROBE_TIMEOUT_S = 2.0
_GEN_TIMEOUT_S = 60.0
_PROBE_TTL_S = 15.0
_TEMPERATURE = 0.2
_NUM_CTX = 2048
_KEEP_ALIVE = "720h"  # 30 days: model stays resident; see llm_keep_alive()

_PREFERRED_MODELS = [
    "qwen2.5:0.5b",
    "tinyllama",
    "llama3.2:1b",
    "phi3:mini",
    "gemma2:2b",
]
_SIZE_HINTS = ["tiny", "mini", "small", "0.5b", "1b", "2b", "3b", "4b"]

_PERSISTED_MODE_KEY = "ai_mode"
_ON_VALUES = {"1", "true", "on", "yes"}
_OFF_VALUES = {"0", "false", "off", "no"}
_probe_cache: dict[str, tuple[float, dict | None]] = {}


def get_persisted_ai_mode() -> str | None:
    """The UI-toggle value from the `settings` table, if present."""
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (_PERSISTED_MODE_KEY,)).fetchone()
    except Exception:
        return None
    return None if row is None else row["value"]


def set_persisted_ai_mode(mode_: str) -> None:
    """Upsert the UI toggle preference. Choice: on / off."""
    with db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = datetime('now')",
            (_PERSISTED_MODE_KEY, mode_))


def clear_persisted_ai_mode() -> None:
    """Drop the persisted preference (used by tests for isolation)."""
    with db() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?",
                     (_PERSISTED_MODE_KEY,))


def mode() -> str:
    """'on' | 'off' | 'auto'.

    Precedence: an explicit LOGSENTINEL_AI_SUMMARY env value wins (deploy
    override); otherwise the DB-persisted UI toggle decides; else 'auto'.
    """
    v = os.environ.get("LOGSENTINEL_AI_SUMMARY", "").strip().lower()
    if v in _ON_VALUES:
        return "on"
    if v in _OFF_VALUES:
        return "off"
    persisted = get_persisted_ai_mode()
    if persisted is not None:
        return persisted
    return "auto"


def switch_on(mode_: str | None = None) -> bool:
    """The user-facing switch: ON for 'auto' and forced 'on'.
    Reachability of an actual model is a separate concern (probe())."""
    return (mode_ if mode_ is not None else mode()) != "off"


def llm_url() -> str:
    return os.environ.get("LOGSENTINEL_LLM_URL", DEFAULT_LLM_URL).rstrip("/")


def _probe(base: str) -> dict | None:
    """GET {base}/api/tags once per TTL: the model manifest when the
    endpoint answers, else None. Cheap enough to run on every status check."""
    now = time.time()
    hit = _probe_cache.get(base)
    if hit and now - hit[0] < _PROBE_TTL_S:
        return hit[1]
    try:
        with urllib.request.urlopen(f"{base}/api/tags",
                                    timeout=_PROBE_TIMEOUT_S) as r:
            if r.status == 200:
                payload = json.loads(r.read().decode("utf-8", "ignore"))
            else:
                payload = None
    except Exception:  # noqa: BLE001 — absence is a normal, supported state
        payload = None
    _probe_cache[base] = (now, payload)
    return payload


def probe() -> bool:
    """True when a local LLM endpoint answers. Cached ~15s per URL."""
    return _probe(llm_url()) is not None


def _installed_models() -> list[str]:
    payload = _probe(llm_url())
    if not payload:
        return []
    return [m.get("name") or m.get("model")
            for m in payload.get("models", []) if m.get("name") or m.get("model")]


def _size_rank(name: str) -> int:
    low = name.lower()
    for i, hint in enumerate(_SIZE_HINTS):
        if hint in low:
            return i
    return len(_SIZE_HINTS)


def llm_model() -> str:
    """Configured model, else the lightest installed, else the tiny default."""
    override = os.environ.get("LOGSENTINEL_LLM_MODEL", "").strip()
    if override:
        return override
    installed = _installed_models()
    if not installed:
        return DEFAULT_MODEL
    for pref in _PREFERRED_MODELS:
        if pref in installed:
            return pref
    return min(installed, key=_size_rank)


def llm_timeout() -> float:
    try:
        return float(os.environ.get("LOGSENTINEL_LLM_TIMEOUT_S",
                                    str(_GEN_TIMEOUT_S)))
    except ValueError:
        return _GEN_TIMEOUT_S


def llm_num_gpu() -> int | None:
    """Optional layer count Ollama may offload; 0 forces CPU-only.
    None (unset/invalid) leaves the decision to Ollama."""
    v = os.environ.get("LOGSENTINEL_LLM_NUM_GPU", "").strip()
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def llm_keep_alive() -> str:
    """How long Ollama keeps the model resident after a call. Default "720h"
    keeps the tiny model loaded for the app's lifetime, so every answer is
    warm and lands in the 2-5s band. Shorten (e.g. "30m") if RAM is tight.
    Ollama rejects "-1" (missing duration unit), so that spelling is
    normalized to the permanent-resident default."""
    raw = os.environ.get("LOGSENTINEL_LLM_KEEP_ALIVE", _KEEP_ALIVE).strip()
    if not raw or raw == "-1":
        return _KEEP_ALIVE
    return raw


def _warm_once() -> None:
    """One tiny generation that loads the model + KV cache in the background."""
    if not probe():
        return
    try:
        generate("Reply with one word: ok.", max_tokens=8)
    except Exception:  # noqa: BLE001 — warming is best-effort
        pass


def warmup(block: bool = False) -> bool:
    """Preload the local model off the hot path, at boot or when requested.

    Spawns a daemon thread (or blocks when block=True, for tests) that issues
    one tiny generation when a local model answers. Never raises; returns True
    when a warm-up attempt was scheduled (a model answered the probe)."""
    if not probe():
        return False
    if block:
        _warm_once()
    else:
        threading.Thread(target=_warm_once, daemon=True).start()
    return True


def generate(prompt: str, max_tokens: int) -> str | None:
    """POST {base}/api/generate with light, small-context options and a
    generous generation timeout. Never raises; returns None on absence."""
    base = llm_url()
    try:
        options = {
            "num_predict": max_tokens,
            "temperature": _TEMPERATURE,
            "num_ctx": _NUM_CTX,
        }
        num_gpu = llm_num_gpu()
        if num_gpu is not None:
            options["num_gpu"] = num_gpu
        req = urllib.request.Request(
            f"{base}/api/generate",
            data=json.dumps({
                "model": llm_model(),
                "prompt": prompt,
                "stream": False,
                "options": options,
                "keep_alive": llm_keep_alive(),
            }).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=llm_timeout()) as r:
            out = json.loads(r.read().decode("utf-8", "ignore"))
        text = str(out.get("response") or "").strip()
        return text or None
    except Exception:  # noqa: BLE001 — callers must never break on LLM absence
        return None