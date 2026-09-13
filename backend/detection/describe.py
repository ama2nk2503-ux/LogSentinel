"""Plain-language 'what was found' narratives (Workstream B).

Fully deterministic template generation — every sentence is derived from the
incident's own already-computed evidence (real event counts, kill-chain stage,
techniques, ML-anomaly reasons, geo hints, recommended response). No LLM, no
fabricated numbers. `describe_incident` narrates an incident; `describe_actor`
narrates an OPSEC actor cluster.
"""

import re

from intelligence.aggregator import RECOMMENDATIONS

_ML_RX = re.compile(r"ML anomaly signal", re.I)
_TAKTIC_READABLE = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource development",
    "initial-access": "initial access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege escalation",
    "defense-evasion": "defense evasion",
    "credential-access": "credential access",
    "discovery": "discovery",
    "lateral-movement": "lateral movement",
    "collection": "collection",
    "command-and-control": "command and control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def _recommendation(categories: str) -> str:
    cats = [c.strip().lower() for c in (categories or "").split(",")]
    for c in cats:
        if c in RECOMMENDATIONS:
            return RECOMMENDATIONS[c]
    return RECOMMENDATIONS["unknown"]


def _span_minutes(timeline: list[dict]) -> int | None:
    stamps = [t.get("ts") for t in timeline if t.get("ts")]
    if len(stamps) < 2:
        return None
    try:
        from datetime import datetime
        parsed = []
        for s in stamps:
            norm = s.replace("Z", "+00:00") if s.endswith("Z") else s
            parsed.append(datetime.fromisoformat(norm))
        span = max(parsed) - min(parsed)
        return max(1, round(span.total_seconds() / 60))
    except ValueError:
        return None


def _facts(inc: dict, sig: dict | None) -> dict:
    timeline = inc.get("timeline") or []
    techniques = inc.get("techniques") or []
    killchain = inc.get("killchain") or {}
    achieved = killchain.get("achieved") or []
    summary = {
        "events": len(timeline),
        "techniques": len(techniques),
        "stages_reached": int(killchain.get("stages_reached") or 0),
        "total_stages": int(killchain.get("total_stages") or 0),
        "tactics": [a.get("tactic") for a in achieved if a.get("tactic")],
        "ml_anomalies": sum(1 for r in (inc.get("reasons") or [])
                            if _ML_RX.search(r)),
        "span_minutes": _span_minutes(timeline),
        "iocs": len(sig["iocs"]) if (sig and sig.get("iocs")) else None,
        "geo_codes": sorted(sig["geo_codes"]) if (sig and sig.get("geo_codes")) else [],
    }
    return summary


def describe_incident(inc: dict, sig: dict | None = None) -> dict:
    """Deterministic one-paragraph narrative of what the evidence shows."""
    title = inc.get("title") or "incident"
    entity = inc.get("entity") or "unknown entity"
    category = (inc.get("category") or "unknown").split(",")[0].strip()
    facts = _facts(inc, sig)
    parts = [
        f"Detected <b>{title}</b> attributed to <b>{entity}</b> — "
        f"{category} activity backed by <b>{facts['events']}</b> correlated "
        f"evidence event(s) (risk score {int(inc.get('risk_score') or 0)})."
    ]

    if facts["stages_reached"]:
        last = facts["tactics"][-1] if facts["tactics"] else None
        readable = _TAKTIC_READABLE.get(last or "", last or "the final stage")
        parts.append(
            f"The actor advanced <b>{facts['stages_reached']}</b> of "
            f"<b>{facts['total_stages']}</b> MITRE ATT&CK stage(s), reaching "
            f"<b>{readable}</b> via {facts['techniques']} mapped technique(s).")

    if facts["ml_anomalies"]:
        parts.append(
            f"<b>{facts['ml_anomalies']}</b> supporting event(s) were flagged "
            f"as statistical anomalies by the isolation-forest model, "
            f"strengthening the signal beyond the rule match alone.")

    if facts["iocs"]:
        ioc_phrase = f"<b>{facts['iocs']}</b> distinct indicator(s) of compromise"
        if facts["geo_codes"]:
            ioc_phrase += f", and source activity resolving to {', '.join(facts['geo_codes'])}"
        parts.append(f"{ioc_phrase} were observed in the evidence.")

    if facts["span_minutes"]:
        parts.append(
            f"The activity unfolded across roughly <b>{facts['span_minutes']}</b> "
            f"minute(s) of event time.")

    return {
        "kind": "what-was-found",
        "title": title,
        "summary": " ".join(parts),
        "facts": facts,
        "recommended_response": _recommendation(inc.get("category") or ""),
        "provenance": ("All figures above are derived deterministically from the "
                       "correlated evidence on this card (no AI model involved)."),
    }


def describe_actor(actor: dict) -> dict:
    """Deterministic narrative for an OPSEC actor cluster."""
    members = actor.get("members") or []
    signals = actor.get("shared_signals") or {}
    iocs = signals.get("reused_iocs") or []
    techs = signals.get("mitre_techniques") or []
    severities = [m.get("severity") for m in members]
    worst = ("CRITICAL" if "CRITICAL" in severities else
             "HIGH" if "HIGH" in severities else
             "MEDIUM" if "MEDIUM" in severities else "LOW")

    parts = [
        f"This actor groups <b>{len(members)}</b> correlated incident(s) "
        f"(stage attributed confidence {actor.get('confidence') or 0.0:.0%}, "
        f"posture {actor.get('posture')}/{100})."]
    if iocs:
        parts.append(f"Their activity reuses <b>{len(iocs)}</b> shared IOC(s) "
                     f"(e.g. {iocs[0]['value']}).")
    if techs:
        parts.append(f"The group repeats <b>{len(techs)}</b> MITRE technique(s) "
                     f"({techs[0]['id']} {techs[0].get('name', '')}).")
    if "beacon_cadence" in str(actor.get("links") or []):
        parts.append("Near-identical command cadence suggests an automated/scheduled actor.")
    parts.append(f"Worst severity carried by a member: <b>{worst}</b>.")

    return {
        "kind": "opsec-actor",
        "actor_id": actor.get("actor_id"),
        "summary": " ".join(parts),
        "facts": {
            "n_incidents": len(members),
            "confidence": actor.get("confidence") or 0.0,
            "posture": actor.get("posture"),
            "reused_iocs": len(iocs),
            "mitre_techniques": len(techs),
            "worst_member_severity": worst,
        },
        "recommended_response": (
            "Treat all entities associated with this actor as correlated and "
            "triage as one campaign; block the shared indicators, reset any "
            "affected credentials, and preserve the evidence for attribution."),
        "provenance": ("Actor grouping is computed from evidence-derived signals; "
                       "posture points and confidence are explained per-item in the "
                       "breakdown below."),
    }