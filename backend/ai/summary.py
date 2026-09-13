"""Optional AI narration (M4, item 10) — auto-on, light, grounded.

An LLM may only narrate a conclusion the deterministic engine already
reached; it never computes one. Hard guarantees:

- Engaged automatically when a small local model answers at a configured
  localhost endpoint (see ai.llm for auto/on/off semantics). Without a
  model the module dials nothing beyond a localhost tags probe and callers
  get a deterministic, explainable narration built from the same evidence.
- Narrations carry the mandated disclaimer and are always returned next
  to the unedited deterministic evidence that produced them.
- Light for any machine: tiny-model auto-pick, capped narration length,
  60s generation timeout (see ai.llm).
- No new dependency: stdlib urllib only, localhost only.
"""

from ai import llm

DISCLAIMER = "AI-generated summary — verify against evidence below."

_NARRATION_MAX_TOKENS = 80


def enabled() -> bool:
    """The user-facing switch: ON for 'auto' and forced 'on'."""
    return llm.switch_on()


def _llm_available() -> bool:
    """True when a local model endpoint answers (cached short-TTL probe)."""
    return llm.probe()


def _prompt_risk(title: str, risk_score: int, reasons: list[str]) -> str:
    return (
        "You are a SOC assistant. Narrate in 2-3 plain sentences why this "
        "incident scored its risk. Use ONLY the facts given; do not invent "
        "details or recommendations beyond them.\n"
        f"Incident: {title}\nRisk score: {risk_score}/100\n"
        "Scored factors (authoritative, do not contradict):\n"
        + "\n".join(f"- {r}" for r in reasons)
    )


def _call_local_llm(prompt: str) -> str | None:
    return llm.generate(prompt, _NARRATION_MAX_TOKENS)


def _deterministic_fallback(title: str, risk_score: int, reasons: list[str]) -> str:
    """Explainable narration used when the LLM is absent/unreachable —
    templated from the same evidence, no generation involved."""
    head = reasons[0] if reasons else "no scored factors were recorded"
    return (f"Incident '{title}' scored {risk_score}/100. The dominant factor "
            f"was: {head}. " + (f"{len(reasons)} factors contributed in total."
                                if len(reasons) > 1 else ""))


def narrate_risk(title: str, risk_score: int, reasons: list[str]) -> dict | None:
    """Narrate an already-computed risk breakdown. Returns None whenever the
    switch is off or there is nothing to narrate — callers must treat that
    as normal."""
    if not enabled() or not reasons:
        return None
    if _llm_available():
        text = _call_local_llm(_prompt_risk(title, risk_score, reasons))
        if text:
            return {"narration": text, "disclaimer": DISCLAIMER, "source": "local_llm"}
    return {"narration": _deterministic_fallback(title, risk_score, reasons),
            "disclaimer": DISCLAIMER, "source": "deterministic_template"}
