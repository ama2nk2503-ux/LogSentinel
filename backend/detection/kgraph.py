"""Job knowledge graph: incidents + IOCs + MITRE techniques + entities.

Deterministic, offline graphify-style extraction. Every node carries a
community label and every edge carries honest provenance (EXTRACTED | INFERRED)
plus confidence, so the exported JSON is GraphRAG-ready without ever calling a
model. Community detection over incidents is union-find, so a rerun always
yields the same actor groups.
"""

import json
import re
import statistics
from datetime import datetime

from core import geoip
from core.intel import load_reference
from core.storage import db

LINK_THRESHOLD = 0.5
CONF_CAP = 1.0

WEIGHTS = {
    "ioc": 2.0,
    "ioc_feed": 4.0,
    "technique": 1.5,
    "geo": 0.5,
    "cadence": 1.0,
}

_IP_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _tech_id(t: dict) -> str | None:
    """MITRE technique entries store the id as 'technique' (attack mapping)."""
    return t.get("id") or t.get("technique")


def incident_rows(job_id: str) -> list[dict]:
    """All correlated incidents for a job, JSON columns deserialised."""
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM correlations WHERE job_id = ? ORDER BY risk_score DESC, id",
            (job_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["techniques"] = json.loads(d.pop("techniques_json") or "[]")
        d["killchain"] = json.loads(d.pop("killchain_json") or "{}")
        d["event_ids"] = json.loads(d.pop("evidence_event_ids_json") or "[]")
        d["timeline"] = json.loads(d.pop("timeline_json") or "[]")
        d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        out.append(d)
    return out


def _ts_epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    norm = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(norm).timestamp()
    except ValueError:
        return None


def _cadence_seconds(timeline: list[dict]) -> float | None:
    stamps = sorted({e for e in (_ts_epoch(t.get("ts")) for t in timeline) if e is not None})
    if len(stamps) < 3:
        return None
    gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b - a > 0]
    if len(gaps) < 2:
        return None
    return statistics.median(gaps)


def entity_ip(entity: str | None) -> str | None:
    """First IPv4 part of an incident entity string like 'ip:user'."""
    for part in (entity or "").split(":"):
        part = part.strip()
        if part and _IP_RX.match(part):
            try:
                if all(0 <= int(o) <= 255 for o in part.split(".")):
                    return part
            except ValueError:
                pass
    return None


def event_map(job_id: str, event_ids: list[str]) -> dict[str, dict]:
    """event_id -> {src_ip, geo, iocs} for the evidence events of a job."""
    if not event_ids:
        return {}
    unique = sorted(set(event_ids))
    rows = []
    with db() as conn:
        for start in range(0, len(unique), 400):
            chunk = unique[start:start + 400]
            ph = ",".join("?" * len(chunk))
            rows += conn.execute(
                f"SELECT event_id, iocs_json, src_ip, dst_ip FROM events"
                f" WHERE job_id = ? AND event_id IN ({ph})",
                (job_id, *chunk)).fetchall()
    out = {}
    for r in rows:
        geo = None
        for ip in (r["src_ip"], r["dst_ip"]):
            if not ip:
                continue
            g = geoip.lookup(ip)
            if g and geoip.is_public(g):
                geo = g
                break
        out[r["event_id"]] = {
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "geo": geo,
            "iocs": json.loads(r["iocs_json"] or "[]"),
        }
    return out


def incident_signal_vector(inc: dict, events_by_id: dict) -> dict:
    """Weighted signal vector used for pairwise incident linkage.

    Signals: reused IOCs (feed-backed weighted x2), shared MITRE technique ids,
    source-country geo, and beacon cadence. `weight` is the total signal mass
    used to normalise pair confidence.
    """
    feed = load_reference()
    iocs: dict[tuple, dict] = {}
    geo_codes: set[str] = set()
    for eid in inc["event_ids"]:
        ev = events_by_id.get(eid)
        if not ev:
            continue
        for ioc in ev.get("iocs", []) or []:
            value = str(ioc.get("value", "") or "").strip().lower()
            if not value:
                continue
            key = (str(ioc.get("type", "indicator")), value)
            iocs.setdefault(key, ioc)
        geo = ev.get("geo")
        if geo and geoip.is_public(geo):
            geo_codes.add(geo.get("country_code") or (geo.get("country") or ""))
    entity = entity_ip(inc.get("entity", ""))
    if entity:
        geo = geoip.lookup(entity)
        if geo and geoip.is_public(geo):
            geo_codes.add(geo.get("country_code") or (geo.get("country") or ""))

    techniques = {_tech_id(t): t for t in inc["techniques"]
                  if _tech_id(t) is not None}
    cadence = _cadence_seconds(inc["timeline"])

    vector = {"iocs": iocs, "techniques": techniques, "geo_codes": geo_codes,
              "cadence": cadence}

    weight = 0.0
    for key, ioc in iocs.items():
        if feed.get(key[1]):
            vector.setdefault("feed_iocs", {})[key] = ioc
            weight += WEIGHTS["ioc_feed"]
        else:
            weight += WEIGHTS["ioc"]
    weight += len(techniques) * WEIGHTS["technique"]
    if geo_codes:
        weight += WEIGHTS["geo"]
    if cadence is not None:
        weight += WEIGHTS["cadence"]
    vector["weight"] = weight
    return vector


def shared_signals(a: dict, b: dict) -> tuple[float, list[dict]]:
    """Weighted shared signal mass + provenance-stamped notes for a pair."""
    feed = load_reference()
    shared_weight = 0.0
    notes: list[dict] = []

    for key, ioc in a["iocs"].items():
        if key not in b["iocs"]:
            continue
        is_feed = feed.get(key[1]) is not None
        w = WEIGHTS["ioc_feed"] if is_feed else WEIGHTS["ioc"]
        shared_weight += w
        notes.append({
            "signal": "reused_ioc",
            "value": key[1],
            "ioc_type": key[0],
            "confidence": round(ioc.get("confidence") or w / WEIGHTS["ioc_feed"], 3),
            "provenance": "EXTRACTED",
            "evidence": ("IOC appears in the evidence events of both incidents; "
                         "also present in the bundled intel reference feed"
                         if is_feed else
                         "IOC appears in the evidence events of both incidents within the same job"),
        })

    for tid, t in a["techniques"].items():
        if tid in b["techniques"]:
            shared_weight += WEIGHTS["technique"]
            notes.append({
                "signal": "shared_technique",
                "value": tid,
                "name": t.get("name") or tid,
                "provenance": "EXTRACTED",
                "evidence": "Both incidents map to the same MITRE technique id via rule attack mappings",
            })

    common_geo = a["geo_codes"] & b["geo_codes"]
    if a["geo_codes"] and b["geo_codes"] and common_geo:
        shared_weight += WEIGHTS["geo"]
        notes.append({
            "signal": "shared_geo",
            "value": ", ".join(sorted(common_geo)),
            "provenance": "INFERRED",
            "evidence": "Both incidents resolve to public addresses in the same country range (GeoIP lookup)",
        })

    if a["cadence"] is not None and b["cadence"] is not None:
        lo, hi = min(a["cadence"], b["cadence"]), max(a["cadence"], b["cadence"])
        if hi <= max(3.0, lo * 1.25):
            shared_weight += WEIGHTS["cadence"]
            notes.append({
                "signal": "beacon_cadence",
                "value": f"{lo:.1f}s vs {hi:.1f}s",
                "provenance": "INFERRED",
                "evidence": "Inter-command time gaps across both incidents are near-identical (beaconing pattern)",
            })

    return shared_weight, notes


def incident_links(job_id: str, threshold: float = LINK_THRESHOLD) -> list[dict]:
    """All confidence-linked incident pairs for a job (sorted best first)."""
    incs = incident_rows(job_id)
    if len(incs) < 2:
        return []
    eids = sorted({e for i in incs for e in i["event_ids"]})
    events_by_id = event_map(job_id, eids)
    vectors = {i["id"]: incident_signal_vector(i, events_by_id) for i in incs}

    links = []
    for i in range(len(incs)):
        for j in range(i + 1, len(incs)):
            a, b = incs[i], incs[j]
            shared_weight, notes = shared_signals(vectors[a["id"]], vectors[b["id"]])
            if shared_weight <= 0:
                continue
            denom = max(1.0, min(vectors[a["id"]]["weight"], vectors[b["id"]]["weight"]))
            confidence = round(min(CONF_CAP, shared_weight / denom), 3)
            if confidence < threshold:
                continue
            links.append({
                "source": a["id"],
                "target": b["id"],
                "source_title": a["title"],
                "target_title": b["title"],
                "weighted_shared": round(shared_weight, 3),
                "confidence": confidence,
                "signals": notes,
            })
    links.sort(key=lambda x: x["confidence"], reverse=True)
    return links


def community_labels(links: list[dict], node_ids: list) -> dict[str, str]:
    """Union-find communities over incident links -> 'actor-N' labels."""
    ids = list(node_ids)
    parent = {n: n for n in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for link in links:
        if link["source"] in parent and link["target"] in parent:
            union(link["source"], link["target"])

    groups: dict[str, list[str]] = {}
    for n in ids:
        groups.setdefault(find(n), []).append(n)

    labels = {}
    for idx, members in enumerate(
            sorted(groups.values(), key=lambda m: len(m), reverse=True), start=1):
        for m in members:
            labels[m] = f"actor-{idx}"
    return labels


def build_job_graph(job_id: str) -> dict:
    """GraphRAG-ready knowledge graph for a job (graphify graph.json shape)."""
    feed = load_reference()
    incs = incident_rows(job_id)
    eids = sorted({e for i in incs for e in i["event_ids"]})
    events_by_id = event_map(job_id, eids)
    vectors = {i["id"]: incident_signal_vector(i, events_by_id) for i in incs}
    links = incident_links(job_id, LINK_THRESHOLD)
    labels = community_labels(links, [i["id"] for i in incs])

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    def add_node(nid, label, ntype, community="", meta=None):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "type": ntype,
                      "community": community, "meta": meta or {}})

    def add_edge(source, target, kind, confidence, weight, label, evidence=""):
        edges.append({"source": source, "target": target, "kind": kind,
                      "confidence": round(min(CONF_CAP, confidence), 3),
                      "weight": round(weight, 3), "label": label,
                      "evidence": evidence})

    for inc in sorted(incs, key=lambda x: x["risk_score"], reverse=True):
        add_node(f"inc:{inc['id']}", inc["title"], "incident",
                 community=labels.get(inc["id"], ""),
                 meta={"entity": inc["entity"], "severity": inc["severity"],
                       "risk_score": int(inc["risk_score"] or 0),
                       "classification": inc["classification"]})

    for inc in incs:
        iid = f"inc:{inc['id']}"
        community = labels.get(inc["id"], "")
        for t in inc["techniques"]:
            ttid = _tech_id(t)
            if ttid is None:
                continue
            tid = f"ttp:{ttid}"
            add_node(tid, t.get("name") or ttid, "technique",
                     community=community, meta={"technique_id": ttid})
            add_edge(iid, tid, "EXTRACTED", 1.0, WEIGHTS["technique"],
                     "uses technique",
                     "From the incident's correlated rules mapped to MITRE ATT&CK")
        for key, ioc in vectors[inc["id"]]["iocs"].items():
            nid = f"ioc:{key[0]}:{key[1]}"
            feed_backed = feed.get(key[1]) is not None
            add_node(nid, key[1], "ioc", community=community,
                     meta={"ioc_type": key[0],
                           "feed_backed": feed_backed,
                           "confidence": ioc.get("confidence")})
            add_edge(iid, nid, "EXTRACTED", 1.0,
                     WEIGHTS["ioc_feed"] if feed_backed else WEIGHTS["ioc"],
                     "references IOC",
                     "IOC extracted from the incident's evidence events")
        for part in (inc["entity"] or "").split(":"):
            part = part.strip()
            if not part or part == "-":
                continue
            nid = f"ent:{part}"
            add_node(nid, part, "entity", community=community,
                     meta={"kind": "ip" if _IP_RX.match(part) else "identity"})
            add_edge(iid, nid, "EXTRACTED", 1.0, 1.0, "involves entity",
                     "Entity is the primary attribute of the correlated incident")

    for link in links:
        add_edge(link["source"], link["target"], "INFERRED", link["confidence"],
                 link["weighted_shared"], "shares actor signals",
                 "Linked by " + ", ".join(s["signal"] for s in link["signals"]))

    counts: dict[str, int] = {}
    for n in nodes:
        if n["community"]:
            counts[n["community"]] = counts.get(n["community"], 0) + 1

    return {
        "job_id": job_id,
        "n_incidents": len(incs),
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "n_nodes": len(nodes),
            "n_edges": len(edges),
            "n_communities": len(counts),
            "link_threshold": LINK_THRESHOLD,
            "communities": [{"id": c, "n_nodes": n}
                            for c, n in sorted(counts.items())],
        },
    }