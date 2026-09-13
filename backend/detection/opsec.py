"""OPSEC actor attribution (Workstream A).

Groups correlated incidents into actor clusters — the communities detected by
the job knowledge graph (detection.kgraph) — and scores each cluster's
operational posture with a fully explained, provenance-stamped breakdown.
Every decision is honest: EXTRACTED means the signal came from actual evidence,
INFERRED means it is a weak/secondary signal that broadens the link.
"""

from core.intel import load_reference
from detection.kgraph import (LINK_THRESHOLD, community_labels, event_map,
                              incident_links, incident_rows,
                              incident_signal_vector)

_BASE_POSTURE = 15
_MAX_POSTURE = 100


def _group_posture(members: list[dict], links: list[dict], feed: dict) -> tuple[int, list[dict], float]:
    points = 0
    breakdown: list[dict] = []

    def add(p, reason, provenance):
        nonlocal points
        points = min(_MAX_POSTURE, points + p)
        breakdown.append({"points": p, "reason": reason, "provenance": provenance})

    add(_BASE_POSTURE, "Baseline posture for any evidence-backed activity cluster",
        "INFERRED")

    shared_iocs: dict[str, int] = {}
    shared_techs: dict[str, dict] = {}
    has_geo = False
    has_cadence = False
    for link in links:
        for s in link["signals"]:
            if s["signal"] == "reused_ioc":
                shared_iocs[s["value"]] = shared_iocs.get(s["value"], 0) + 1
            elif s["signal"] == "shared_technique":
                shared_techs[s["value"]] = {"name": s.get("name", s["value"])}
            elif s["signal"] == "shared_geo":
                has_geo = True
            elif s["signal"] == "beacon_cadence":
                has_cadence = True

    for value, count in shared_iocs.items():
        add(5 * count, f"{count} incident(s) reuse the IOC {value}", "EXTRACTED")
        if feed.get(value):
            add(10, f"IOC {value} is present in the bundled intel reference feed",
                "EXTRACTED")
    for tid, meta in shared_techs.items():
        add(3, f"Shared MITRE technique {tid} ({meta['name']}) across incidents",
            "EXTRACTED")
    if has_geo:
        add(4, "Incidents resolve to the same public geo ranges (GeoIP)",
            "INFERRED")
    if has_cadence:
        add(4, "Near-identical inter-command cadence suggests scheduled/automated actor",
            "INFERRED")

    for m in members:
        severity = m.get("severity") or ""
        if severity == "CRITICAL":
            add(6, f"\"{m['title']}\" is CRITICAL (risk {m.get('risk_score')})",
                "EXTRACTED")
        elif severity == "HIGH":
            add(3, f"\"{m['title']}\" is HIGH (risk {m.get('risk_score')})",
                "EXTRACTED")
        stages = int((m.get("killchain") or {}).get("stages_reached") or 0)
        if stages:
            add(min(20, stages * 2),
                f"Kill-chain reaches ATT&CK stage {stages} of the progression",
                "EXTRACTED")

    confidence = round(sum(l["confidence"] for l in links) / len(links), 3) if links else 0.0
    return points, breakdown, confidence


def build_actor_groups(job_id: str, threshold: float = LINK_THRESHOLD) -> dict:
    """Actor clusters + posture for a job (empty-safe)."""
    incs = incident_rows(job_id)
    if not incs:
        return {"job_id": job_id, "n_actors": 0, "n_incidents": 0,
                "actors": [], "posture_summary": {"max": 0, "mean": 0}}

    links = incident_links(job_id, threshold)
    eids = sorted({e for i in incs for e in i["event_ids"]})
    events_by_id = event_map(job_id, eids)
    vectors = {i["id"]: incident_signal_vector(i, events_by_id) for i in incs}
    labels = community_labels(links, [i["id"] for i in incs])
    feed = load_reference()

    groups: dict[str, list[dict]] = {}
    for inc in incs:
        key = labels.get(inc["id"], "actor-1")
        groups.setdefault(key, []).append(inc)

    actors = []
    for actor_id, members in sorted(groups.items(),
                                    key=lambda kv: len(kv[1]), reverse=True):
        member_ids = {m["id"] for m in members}
        group_links = [l for l in links
                       if l["source"] in member_ids and l["target"] in member_ids]
        posture, breakdown, confidence = _group_posture(members, group_links, feed)

        shared_iocs: dict[str, int] = {}
        shared_techs: list[dict] = []
        for link in group_links:
            for s in link["signals"]:
                if s["signal"] == "reused_ioc":
                    shared_iocs[s["value"]] = shared_iocs.get(s["value"], 0) + 1
                elif s["signal"] == "shared_technique":
                    if not any(e.get("id") == s["value"] for e in shared_techs):
                        shared_techs.append({"id": s["value"],
                                             "name": s.get("name", s["value"])})

        actors.append({
            "actor_id": actor_id,
            "n_incidents": len(members),
            "members": [{
                "id": m["id"], "title": m["title"], "entity": m["entity"],
                "severity": m["severity"], "risk_score": int(m["risk_score"] or 0),
                "classification": m["classification"],
            } for m in members],
            "confidence": confidence,
            "posture": posture,
            "posture_breakdown": breakdown,
            "shared_signals": {
                "reused_iocs": [{"value": v, "incidents": c}
                                for v, c in sorted(shared_iocs.items())],
                "mitre_techniques": shared_techs,
            },
            "links": [{k: v for k, v in l.items()} for l in group_links],
        })

    postures = [a["posture"] for a in actors]
    return {
        "job_id": job_id,
        "link_threshold": threshold,
        "n_actors": len(actors),
        "n_incidents": len(incs),
        "actors": actors,
        "posture_summary": {
            "max": max(postures) if postures else 0,
            "mean": round(sum(postures) / len(postures), 1) if postures else 0,
        },
        "knowledge_graph": f"/api/knowledge/{job_id}",
    }