"""ATT&CK enrichment: rule mappings + per-entity kill-chain progression."""

import json
from functools import lru_cache

from core.config import settings
from core.storage import db


@lru_cache(maxsize=1)
def load_mapping() -> tuple[dict, list[str]]:
    with open(settings.attack_mapping_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("mappings", {}), data.get("_tactic_order", [])


def reload_mapping() -> None:
    load_mapping.cache_clear()


def tactics_order() -> list[str]:
    return load_mapping()[1]


def mapping_for(rule_id: str) -> list[dict]:
    return load_mapping()[0].get(rule_id, [])


def enrich_job(job_id: str) -> int:
    """Attach techniques to detections; build kill-chain per incident."""
    with db() as conn:
        dets = conn.execute(
            "SELECT id, rule_id FROM detections WHERE job_id = ?",
            (job_id,)).fetchall()
        for d in dets:
            conn.execute(
                "UPDATE detections SET techniques_json = ? WHERE id = ?",
                (json.dumps(mapping_for(d["rule_id"])), d["id"]))

        incs = conn.execute(
            "SELECT id, timeline_json FROM correlations WHERE job_id = ?",
            (job_id,)).fetchall()

    updated = 0
    with db() as conn:
        for inc in incs:
            timeline = json.loads(inc["timeline_json"] or "[]")
            # Kill-chain derives strictly from the incident's own correlated
            # evidence: every timeline entry carries the rule that fired.
            rule_ids = [t.get("rule_id") for t in timeline if t.get("rule_id")]
            killchain = _build_killchain_from_rules(rule_ids)
            techniques_all, seen = [], set()
            for rid in dict.fromkeys(rule_ids):
                for t in mapping_for(rid):
                    if t["technique"] not in seen:
                        seen.add(t["technique"])
                        techniques_all.append(t)
            conn.execute(
                "UPDATE correlations SET techniques_json = ?, killchain_json = ? WHERE id = ?",
                (json.dumps(techniques_all), json.dumps(killchain), inc["id"]))
            updated += 1
    return updated


def _build_killchain_from_rules(rule_ids: list[dict | str]) -> dict:
    order = tactics_order()
    achieved: dict[str, dict] = {}
    counts: dict[str, int] = {}
    for rid in rule_ids:
        counts[rid] = counts.get(rid, 0) + 1
        for t in mapping_for(rid):
            tactic = t.get("tactic")
            slot = achieved.setdefault(tactic, {"tactic": tactic, "techniques": [],
                                                "evidence_count": 0})
            if not any(x["id"] == t["technique"] for x in slot["techniques"]):
                slot["techniques"].append({"id": t["technique"], "name": t["name"]})
    # evidence weight = number of timeline events mapped through each technique's rule
    for a in achieved.values():
        total = 0
        for t in a["techniques"]:
            for rid, cnt in counts.items():
                if any(m["technique"] == t["id"] for m in mapping_for(rid)):
                    total += cnt
                    break
        a["evidence_count"] = total
    ordered = sorted(achieved.values(),
                     key=lambda x: order.index(x["tactic"]) if x["tactic"] in order else 99)
    stage_index = max((order.index(a["tactic"]) for a in ordered if a["tactic"] in order),
                      default=-1)
    return {
        "tactics_order": order,
        "achieved": ordered,
        "stages_reached": stage_index + 1,
        "total_stages": len(order),
        "progress_pct": round(((stage_index + 1) / len(order)) * 100) if order else 0,
    }
