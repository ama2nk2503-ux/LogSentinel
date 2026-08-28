"""Investigation timeline: phase-clustered incident evidence for triage.

Each correlated timeline entry carries the rule that fired; rules map to MITRE
ATT&CK tactics (rules/attack_mapping.json), so the investigation view clusters
evidence into an ordered attack-phase progression.
"""

import json

from core.storage import db
from detection.attack import load_mapping


def build_timeline(incident_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT id, job_id, title, category, severity, risk_score, created_at,"
            " timeline_json FROM correlations WHERE id = ?",
            (incident_id,)).fetchone()
        if row is None:
            return None
        inc = dict(row)

    timeline = json.loads(inc["timeline_json"] or "[]")
    mappings, order = load_mapping()
    phases: dict[str, dict] = {}
    unmapped: set[str] = set()
    for entry in timeline:
        rid = entry.get("rule_id")
        mapped = mappings.get(rid, []) if rid else []
        tactic = mapped[0].get("tactic", "unmapped") if mapped else "unmapped"
        phase = phases.setdefault(tactic, {"tactic": tactic, "entries": []})
        phase["entries"].append(entry)
        if not mapped:
            unmapped.add(rid or "")

    out_phases = []
    for phase in phases.values():
        entries = sorted(phase["entries"], key=lambda e: e.get("ts") or "")
        out_phases.append({
            "tactic": phase["tactic"],
            "count": len(entries),
            "start": entries[0].get("ts") or None,
            "end": entries[-1].get("ts") or None,
            "entries": entries,
        })
    out_phases.sort(key=lambda p: order.index(p["tactic"]) if p["tactic"] in order else 99)

    return {
        "incident_id": inc["id"],
        "job_id": inc["job_id"],
        "title": inc["title"],
        "category": inc["category"],
        "severity": inc["severity"],
        "risk_score": inc["risk_score"],
        "created_at": inc["created_at"],
        "tactics_order": order,
        "phases": out_phases,
        "unmapped_rule_ids": sorted(t for t in unmapped if t),
    }