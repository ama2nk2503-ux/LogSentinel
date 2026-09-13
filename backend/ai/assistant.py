"""AI chat assistant (session chat) — auto-on, light, grounded.

The LLM is engaged automatically whenever a small local model answers at a
configured localhost endpoint (see ai.llm for the auto/on/off semantics).
Without a model the module dials nothing beyond a localhost tags probe and
callers get a deterministic, intent-routed answer built purely from stored
facts — never an error — so the app runs and passes all tests identically.

Hard guarantees (shared with ai.llm):

- The LLM may only answer using the deterministic fact packet the engine
  already computed: event health, correlated incidents with remediation,
  fired rules, IOCs, intel/geo, and raw matching events. It may expand on
  general mitigation advice for threats that are present, but may never
  invent detections, counts, or dataset claims.
- Answers always carry the mandated disclaimer alongside the facts used.
- Light for any machine: tiny-model auto-pick, capped prompt facts, capped
  generation length, 60s generation timeout (see ai.llm).
- No new dependency: stdlib urllib only, localhost only.
"""

import json
import re

from ai import llm
from api.routes_query import query_events
from core.storage import db
from detection.intent import parse_intent
from intelligence.aggregator import _recommendation

DISCLAIMER = "AI-generated summary — verify against evidence below."

_MAX_HISTORY_TURNS = 4
_ASSIST_MAX_TOKENS = 90
_MAX_PROMPT_FACTS = 22
_HISTORY_MAX_CHARS = 300
_FACT_MAX_CHARS = 350

_FIX_RX = re.compile(r"(fix|fixed|fixing|how\s+do\s+i|how\s+to|stop|prevent|"
                     r"harden|remediat\w*|mitigat\w*|block|\badvice\b|solution|"
                     r"resolve|solve)", re.I)
_ERROR_RX = re.compile(r"\b(error|errors|failed|failure|fail|crash|exception)\b", re.I)
_SHOW_RX = re.compile(r"\b(show|list|find|found|which|display|see|look)\b", re.I)
_ATTACK_RX = re.compile(r"\b(attack|attacks|threat|incident|suspicious|malware|"
                        r"brute|exploit|breach|compromise|scan|recon)\b", re.I)


def enabled() -> bool:
    """The user-facing switch: ON for 'auto' and forced 'on'."""
    return llm.switch_on()


def _llm_available() -> bool:
    """True when a local model endpoint answers (cached short-TTL probe)."""
    return llm.probe()


def llm_url() -> str:
    return llm.llm_url()


def llm_model() -> str:
    return llm.llm_model()


def assistant_status() -> dict:
    """Report AI mode, the reachable-model probe, and the pickable model.

    The availability probe is lazy: it never runs while mode is 'off'.
    """
    m = llm.mode()
    switch = llm.switch_on(m)
    available = llm.probe() if switch else False
    return {
        "mode": m,
        "enabled": switch,
        "llm_available": available,
        "llm_url": llm_url(),
        "model": llm_model() if available else None,
        "model_hint": (f"Install a tiny local model, e.g. `ollama pull"
                       f" {llm.DEFAULT_MODEL}`, to switch AI on")
        if switch and not available else None,
    }


def _fetch_job(job_id: str) -> dict | None:
    with db() as conn:
        job = conn.execute(
            "SELECT id, filename, status, stage, detected_format,"
            " format_confidence, stats_json FROM jobs WHERE id = ?",
            (job_id,)).fetchone()
        if job is None:
            return None
        stats = json.loads(job["stats_json"] or "{}")
        incidents = conn.execute(
            "SELECT title, category, classification, severity, entity,"
            " risk_score, reasons_json FROM correlations"
            " WHERE job_id = ? ORDER BY risk_score DESC",
            (job_id,)).fetchall()
        detections = conn.execute(
            "SELECT rule_name, severity, category, entity, risk_score"
            " FROM detections WHERE job_id = ? ORDER BY risk_score DESC",
            (job_id,)).fetchall()
        extras_rows = conn.execute(
            "SELECT extras_json FROM events"
            " WHERE job_id = ? AND extras_json != '{}' LIMIT 200",
            (job_id,)).fetchall()
        health = conn.execute(
            "SELECT COUNT(*) c, MIN(ts) mn, MAX(ts) mx FROM events"
            " WHERE job_id = ?", (job_id,)).fetchone()
        failed = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE job_id = ?"
            " AND (UPPER(IFNULL(status,'')) IN ('FAILED','ERROR','DENIED','REJECTED')"
            "   OR event_type LIKE '%error%')", (job_id,)).fetchone()
        event_types = conn.execute(
            "SELECT event_type t, COUNT(*) c FROM events WHERE job_id = ?"
            " GROUP BY event_type ORDER BY c DESC LIMIT 8", (job_id,)).fetchall()
        sev = conn.execute(
            "SELECT severity s, COUNT(*) c FROM events WHERE job_id = ?"
            " GROUP BY severity", (job_id,)).fetchall()
        top_msgs = conn.execute(
            "SELECT message m, COUNT(*) c FROM events WHERE job_id = ?"
            " AND IFNULL(message,'') != '' GROUP BY message"
            " ORDER BY c DESC, MIN(ts) DESC LIMIT 5", (job_id,)).fetchall()
        iocs = conn.execute(
            "SELECT json_extract(j.value,'$.value') value,"
            " json_extract(j.value,'$.type') type, COUNT(*) c"
            " FROM events, json_each(events.iocs_json) j"
            " WHERE events.job_id = ? GROUP BY value, type"
            " ORDER BY c DESC LIMIT 8", (job_id,)).fetchall()

    intel_hits, geo_hits = [], []
    for r in extras_rows:
        extras = json.loads(r["extras_json"] or "{}")
        im = extras.get("intel_match") or {}
        if im and (im.get("value") or im.get("threat_type")):
            hit = {"type": im.get("type", "intel"), "value": im.get("value", ""),
                   "confidence": im.get("confidence", 0)}
            if hit not in intel_hits:
                intel_hits.append(hit)
        geo = extras.get("geo") or {}
        g = {"ip": geo.get("ip", ""), "country_code": geo.get("country_code", ""),
             "country": geo.get("country", "")}
        if g["country"] and g not in geo_hits:
            geo_hits.append(g)

    incident_list = [{
        "title": r["title"],
        "category": r["category"],
        "classification": r["classification"],
        "severity": r["severity"],
        "entity": r["entity"],
        "risk_score": int(r["risk_score"] or 0),
        "reasons": json.loads(r["reasons_json"] or "[]"),
    } for r in incidents]
    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    return {
        "job": {
            "id": job["id"],
            "filename": job["filename"],
            "status": job["status"],
            "stage": job["stage"],
            "detected_format": job["detected_format"],
            "format_confidence": job["format_confidence"],
            "total_lines": stats.get("total_lines"),
            "total_iocs": stats.get("total_iocs"),
            "pii_events": stats.get("pii_events"),
            "parsed_lines": stats.get("parsed_lines"),
            "ml_trained": stats.get("ml_trained"),
        },
        "incidents": incident_list,
        "detections": [dict(r) for r in detections],
        "intel_hits": [{"type": h["type"], "value": h["value"],
                        "confidence": h["confidence"]} for h in intel_hits],
        "geo_hits": [{"ip": g["ip"], "country_code": g["country_code"],
                      "country": g["country"]} for g in geo_hits],
        "event_stats": {
            "total_events": int(health["c"] or 0),
            "failed_events": int(failed["c"] or 0),
            "ts_min": health["mn"],
            "ts_max": health["mx"],
            "event_types": [{"type": r["t"], "count": int(r["c"])} for r in event_types],
            "severity_counts": dict(
                sorted(((r["s"] or "LOW"), int(r["c"])) for r in sev)),
            "top_messages": [{"message": r["m"], "count": int(r["c"])}
                             for r in top_msgs],
        },
        "ioc_summary": [{"value": r["value"], "type": r["type"],
                         "count": int(r["c"])} for r in iocs],
        "attack_sweep": [{
            "title": i["title"],
            "classification": i["classification"],
            "severity": i["severity"],
            "risk": i["risk_score"],
            "entity": i["entity"],
            "why": i["reasons"],
            "fix": _recommendation(i["category"]),
        } for i in incident_list],
        "severity_rank": sev_rank,
    }


def _flatten_facts(packet: dict) -> list[str]:
    facts: list[str] = []
    j = packet["job"]
    facts.append(f"Dataset filename: {j['filename']}")
    facts.append(f"Status: {j['status']} ({j['stage']})")
    facts.append(f"Detected format: {j['detected_format']}"
                 f" at {j['format_confidence']}% confidence")
    if j.get("total_lines") is not None:
        facts.append(f"Total lines parsed: {j['total_lines']}")
    if j.get("total_iocs") is not None:
        facts.append(f"Total IOCs extracted: {j['total_iocs']}")
    if j.get("pii_events") is not None:
        facts.append(f"Events with PII: {j['pii_events']}")
    if j.get("ml_trained"):
        facts.append("ML anomaly model trained and ran on this dataset")

    es = packet["event_stats"]
    if es.get("total_events") is not None:
        facts.append(f"Total events recorded: {es['total_events']}")
        facts.append(f"Failed/error events: {es.get('failed_events', 0)}")
    if es.get("ts_min"):
        facts.append(f"Timestamps span {es['ts_min']} → {es['ts_max']}")
    for t in es.get("event_types") or []:
        facts.append(f"Event type '{t['type']}': {t['count']}")
    sev = es.get("severity_counts") or {}
    if sev:
        rank = packet["severity_rank"]
        ordered = sorted(sev.items(), key=lambda kv: rank.get(kv[0], 9))
        facts.append("Severity of events: " + ", ".join(f"{k}={v}" for k, v in ordered))
    for m in es.get("top_messages") or []:
        facts.append(f"Top message ({m['count']} hits): {m['message']}")

    sweep = packet["attack_sweep"]
    for s in sweep:
        why = " ".join(s["why"][:3]) if s["why"] else "no scored reasons"
        facts.append(
            f"Incident '{s['title']}' ({s['classification']}, {s['severity']},"
            f" risk {s['risk']}, entity {s['entity']}) — {why}."
            f" Remediation: {s['fix']}")
    if not sweep:
        facts.append("No threat incidents were correlated for this dataset")
    for det in packet["detections"]:
        facts.append(f"Detection rule '{det['rule_name']}' ({det['category']},"
                     f" {det['severity']}) on {det['entity']}, risk {det['risk_score']}")
    for ioc in packet["ioc_summary"]:
        facts.append(f"IOC {ioc['value']} ({ioc['type']}) seen in {ioc['count']} events")
    for hit in packet["intel_hits"]:
        facts.append(f"Intel hit: {hit['type']}={hit['value']}"
                     f" (confidence {hit['confidence']})")
    for g in packet["geo_hits"]:
        facts.append(f"Geo: {g['ip']} → {g['country']} ({g['country_code']})")
    return facts


def _evidence(job_id: str, question: str) -> dict | None:
    """Pull raw matching events when the question has a structured intent.

    None when the intent is unstructured (packet-level facts already cover
    it) or when nothing matches — never an error.
    """
    parsed = parse_intent(question)
    if parsed["filters"].get("fallback_text"):
        return None
    filters = dict(parsed["filters"])
    filters["_text"] = question
    out = query_events(job_id, filters, limit=12)
    return out if out["total"] else None


def _evidence_facts(evidence: dict) -> list[str]:
    lines = []
    if not evidence:
        return lines
    for e in evidence["events"]:
        target = e.get("dst_ip") or e.get("username") or "?"
        lines.append(
            f"Evidence event [{e.get('ts')}] {e.get('event_type')}"
            f" {e.get('src_ip') or '?'}→{target}"
            f" sev {e.get('severity', 'LOW')} risk {e.get('risk_score', 0)}:"
            f" {(e.get('message') or '').strip()[:120]}")
    return lines


def _prompt(question: str, history: list[dict], facts: list[str]) -> str:
    turns = _MAX_HISTORY_TURNS
    lines = [
        "You are a SOC assistant. Answer the user's question using ONLY the",
        "authoritative facts below (event health, correlated incidents with",
        "remediation, fired rules, IOCs, intel/geo, and raw matching events),",
        "all produced by the deterministic engine. You may expand on general",
        "mitigation advice for the threats that are present, but you must",
        "never invent detections, event counts, or dataset facts that are not",
        "in the facts. If the facts are insufficient, say so plainly. Answer",
        "in 1-3 short sentences, at most 50 words: no preamble, no closing.",
        "",
    ]
    if history:
        last = history[-turns:]
        lines.append("Earlier conversation (for context):")
        for m in last:
            who = "user" if m.get("role") == "user" else "assistant"
            content = str(m.get("content", ""))[:_HISTORY_MAX_CHARS]
            lines.append(f"{who}: {content}")
        lines.append("")
    lines.append("Facts:")
    lines.extend(f"- {f[:_FACT_MAX_CHARS]}" for f in facts)
    lines.append("")
    lines.append(f"Question: {question}")
    lines.append("Answer:")
    return "\n".join(lines)


def _call_local_llm(prompt: str) -> str | None:
    return llm.generate(prompt, _ASSIST_MAX_TOKENS)


def _remediation_answer(packet: dict) -> str:
    sweep = packet["attack_sweep"]
    if not sweep:
        return ("No correlated incidents are present, so there are no stored "
                "attack signatures to remediate in this dataset.")
    header = (f"Remediation for {len(sweep)} correlated "
              f"{'incident' if len(sweep) == 1 else 'incidents'}:")
    lines = [header]
    for s in sweep[:5]:
        why = "; ".join(s["why"][:2]) if s["why"] else "rule hit"
        lines.append(f"- {s['title']} ({s['severity']}, risk {s['risk']}): {why}. "
                     f"Fix: {s['fix']}")
    return "\n".join(lines)


def _error_answer(packet: dict) -> str:
    es = packet["event_stats"]
    head = (f"Event health for '{packet['job']['filename']}': "
            f"{es.get('failed_events', 0)} of {es.get('total_events', 0)} events "
            f"are failed/error.")
    lines = [head]
    top = es.get("top_messages") or []
    if top:
        lines.append("Most frequent messages:")
        lines += [f"- \"{m['message']}\" (x{m['count']})" for m in top[:3]]
    else:
        lines.append("No distinct message text recorded in this dataset.")
    return "\n".join(lines)


def _evidence_answer(evidence: dict) -> str:
    total = evidence["total"]
    lines = [f"Found {total} matching "
             f"{'event' if total == 1 else 'events'}:"]
    for e in evidence["events"][:6]:
        target = e.get("dst_ip") or e.get("username") or "?"
        lines.append(f"- [{e.get('ts')}] {e.get('event_type')}"
                     f" {e.get('src_ip') or '?'}→{target}"
                     f" sev {e.get('severity', 'LOW')} risk {e.get('risk_score', 0)}:"
                     f" {(e.get('message') or '').strip()[:120]}")
    if total > len(evidence["events"][:6]):
        lines.append(f"… and {total - len(evidence['events'][:6])} more "
                     "— see EVIDENCE / FACTS USED.")
    return "\n".join(lines)


def _attack_answer(packet: dict) -> str:
    sweep = packet["attack_sweep"]
    if not sweep:
        return "No threat incidents were correlated for this dataset."
    lines = [f"{len(sweep)} correlated "
             f"{'incident' if len(sweep) == 1 else 'incidents'} found:"]
    lines += [f"- {s['title']} ({s['classification']}, {s['severity']},"
              f" risk {s['risk']}, entity {s['entity']})" for s in sweep[:6]]
    if len(sweep) > 6:
        lines.append(f"… and {len(sweep) - 6} more — see EVIDENCE / FACTS USED.")
    return "\n".join(lines)


def _overview_answer(packet: dict, facts: list[str]) -> str:
    j = packet["job"]
    es = packet["event_stats"]
    parts = [
        f"Dataset '{j['filename']}': status {j['status']} ({j['stage']}),"
        f" detected format {j['detected_format']} at {j['format_confidence']}%.",
    ]
    if j.get("total_lines") is not None:
        parts.append(f"{j['total_lines']} lines parsed,"
                     f" {es.get('total_events', 0)} events recorded,"
                     f" {len(packet['incidents'])} incident(s) correlated.")
    parts.append("Ask to 'show' specific events, 'find attacks', 'list errors',"
                 " or ask 'how do I fix' a threat for targeted answers.")
    return "\n".join(parts)


def _deterministic_answer(question: str, packet: dict,
                          evidence: dict | None = None) -> str:
    """Explainable answer used when the LLM is off/unreachable — derived
    directly from the fact packet and (optionally) matching events."""
    if _FIX_RX.search(question):
        return _remediation_answer(packet)
    if _ERROR_RX.search(question):
        return _error_answer(packet)
    if _SHOW_RX.search(question) and evidence and evidence.get("total"):
        return _evidence_answer(evidence)
    if _ATTACK_RX.search(question):
        return _attack_answer(packet)
    return _overview_answer(packet, [])


def assist(job_id: str, question: str, history: list[dict]) -> dict | None:
    """Answer a question about a processed dataset with an optional session
    history. Returns None only when facts cannot be gathered (unknown job —
    callers must 404). Never raises on LLM absence."""
    packet = _fetch_job(job_id)
    if packet is None:
        return None
    facts = _flatten_facts(packet)
    evidence = _evidence(job_id, question)
    facts.extend(_evidence_facts(evidence))

    if enabled() and _llm_available():
        text = _call_local_llm(_prompt(question, history, facts[:_MAX_PROMPT_FACTS]))
        if text:
            return {"question": question, "answer": text, "source": "local_llm",
                    "disclaimer": DISCLAIMER, "facts": facts}
    return {"question": question,
            "answer": _deterministic_answer(question, packet, evidence),
            "source": "deterministic_template", "disclaimer": DISCLAIMER,
            "facts": facts}