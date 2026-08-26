"""Threat intelligence generation: indicator aggregation + incident reports."""

import json

from core.storage import db

RECOMMENDATIONS = {
    "brute force": "Block source IP at the perimeter; enforce account lockout and MFA on targeted accounts.",
    "credential attack": "Disable affected account, force credential reset, and review subsequent activity.",
    "reconnaissance": "Rate-limit or block the source; verify external exposure of probed services.",
    "port scanning": "Rate-limit or block the source; verify external exposure of probed ports.",
    "web attack": "Review WAF/app logs for the payload; patch input validation; add signatures to blocking rules.",
    "malware": "Isolate the host, collect forensics, and rotate credentials used on it.",
    "phishing": "Search mail gateway logs for the indicator; brief targeted users.",
    "data exfiltration": "Quarantine destination; review volumes transferred and DLP coverage.",
    "privilege escalation": "Revoke elevated sessions; audit sudo/root usage paths.",
    "command execution": "Isolate host; capture volatile evidence; rotate credentials.",
    "persistence": "Hunt scheduled tasks/run keys/systemd units on affected hosts; reimage if confirmed.",
    "lateral movement": "Segment network paths; reset credentials transitively reachable.",
    "unknown": "Triage manually with attached evidence.",
}


def _recommendation(categories: str) -> str:
    cats = [c.strip().lower() for c in (categories or "").split(",")]
    for c in cats:
        if c in RECOMMENDATIONS:
            return RECOMMENDATIONS[c]
    return RECOMMENDATIONS["unknown"]


def build_intel(job_id: str) -> dict:
    """Aggregate IOCs -> indicators table; incidents -> human-readable reports."""
    indicators = _aggregate_indicators(job_id)
    reports = _build_reports(job_id)
    with db() as conn:
        for ind in indicators:
            conn.execute(
                "INSERT INTO indicators (value, type, threat_type, severity,"
                " confidence, first_seen, last_seen, related_events)"
                " VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(value, type) DO UPDATE SET"
                " threat_type=excluded.threat_type, severity=excluded.severity,"
                " confidence=excluded.confidence, first_seen=excluded.first_seen,"
                " last_seen=excluded.last_seen, related_events=excluded.related_events",
                (ind["value"], ind["type"], ind["threat_type"], ind["severity"],
                 ind["confidence"], ind["first_seen"], ind["last_seen"],
                 ind["related_events"]),
            )
    return {"indicators": indicators, "reports": reports}


def _aggregate_indicators(job_id: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT json_extract(j.value,'$.value') AS value,
                   json_extract(j.value,'$.type') AS type,
                   COUNT(*) AS related_events,
                   MIN(e.ts) AS first_seen,
                   MAX(e.ts) AS last_seen,
                   AVG(json_extract(j.value,'$.confidence')) AS confidence
            FROM events e, json_each(e.iocs_json) j
            WHERE e.job_id = ?
            GROUP BY value, type
            """,
            (job_id,),
        ).fetchall()
        sev_rows = conn.execute(
            "SELECT severity, entity FROM correlations WHERE job_id = ?",
            (job_id,)).fetchall()

    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    top_sev = "MEDIUM"
    best = 0
    for r in sev_rows:
        rank = sev_rank.get(r["severity"] or "", 2)
        if rank >= best:
            best = rank
            top_sev = r["severity"] or "MEDIUM"
    # threat_type: dominant annotated threat on events containing this IOC
    out = []
    for r in rows:
        with db() as conn:
            tt = conn.execute(
                """
                SELECT e.threat_type, COUNT(*) c FROM events e, json_each(e.iocs_json) j
                WHERE e.job_id=? AND json_extract(j.value,'$.value')=?
                  AND IFNULL(e.threat_type,'') != ''
                GROUP BY e.threat_type ORDER BY c DESC LIMIT 1
                """,
                (job_id, r["value"]),
            ).fetchone()
        out.append({
            "value": r["value"],
            "type": r["type"],
            "threat_type": tt["threat_type"] if tt else "Suspicious Activity",
            "severity": top_sev,
            "confidence": round(min(0.99, r["confidence"] or 0.8), 2),
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "related_events": r["related_events"],
        })
    return out


def _build_reports(job_id: str) -> list[dict]:
    with db() as conn:
        incs = conn.execute(
            "SELECT * FROM correlations WHERE job_id = ? ORDER BY risk_score DESC",
            (job_id,)).fetchall()
    reports = []
    for inc in incs:
        timeline = json.loads(inc["timeline_json"] or "[]")
        reasons = json.loads(inc["reasons_json"] or "[]")
        evidence = [
            {"ts": t.get("ts"), "rule": t.get("rule_name"), "excerpt": t.get("excerpt")}
            for t in timeline[:10]
        ]
        reports.append({
            "title": inc["title"],
            "threat": inc["category"],
            "source": inc["entity"],
            "target": ", ".join(sorted({t.get("rule_id", "") for t in timeline} - {""}))[:120],
            "events": len(timeline),
            "severity": inc["severity"],
            "classification": inc["classification"],
            "risk_score": inc["risk_score"],
            "confidence": round(min(0.99, 0.5 + inc["risk_score"] / 200), 2),
            "evidence": evidence,
            "why": reasons,
            "recommended_response": _recommendation(inc["category"]),
        })
    return reports
