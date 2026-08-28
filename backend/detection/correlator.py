"""Correlator: chain related detections into incidents with evidence timelines.

Deterministic clustering by shared entities + title inference from the
member-rule categories (e.g., brute force followed by command execution
=> Possible Account Compromise). Every incident keeps its full evidence.
"""

import json
import re

from core.storage import db
from detection.classifier import classify_incident, normalize_category
from detection.risk import band, score_detection, score_incident
from ml.model import bump as ml_bump

SUCCESS_NOTE_RX = re.compile(r"successful authentication followed \(([^@)+]+)@")
IDENTITY_LINK_RX = re.compile(r"\+identity-link (\S+)")


def build_incidents(job_id: str) -> list[dict]:
    """Score detections, cluster them per entity, persist incidents."""
    _rescore_detections(job_id)
    dets = _fetch_detections(job_id)
    if not dets:
        return []

    clusters = _cluster_by_entity(dets)
    incidents: list[dict] = []
    for entity_key, members in clusters.items():
        incident = _build_one(job_id, entity_key, members)
        if incident:
            incidents.append(incident)
    _annotate_events(job_id, incidents)
    return incidents


def _rescore_detections(job_id: str) -> None:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, rule_name, severity, category, evidence_json, reasons_json,"
            " entity FROM detections WHERE job_id = ?", (job_id,)).fetchall()
        for r in rows:
            evidence = json.loads(r["evidence_json"] or "[]")
            reasons = json.loads(r["reasons_json"] or "[]")
            has_ioc = any(i.get("confidence", 0) >= 0.9
                          for ev in evidence for i in _ev_iocs(ev))
            # metric/threshold were embedded as reason text by engine — reuse count
            metric_value = len(evidence) or 1
            threshold = 1
            success = any("successful authentication" in x.lower() for x in reasons)
            linked_user = next((m.group(1) for x in reasons
                                if (m := SUCCESS_NOTE_RX.search(x))), None)
            distinct_targets = len({e.get("excerpt", "")[:40] for e in evidence})
            score, new_reasons = score_detection(
                r["severity"], metric_value, threshold, has_ioc, success,
                len(evidence), min(distinct_targets, 5))
            # In-loop ML: anomalous evidence escalates the detection with an
            # explainable reason (IsolationForest anomaly score from ml.model).
            ml_pts, ml_reason = ml_bump(evidence, job_id)
            if ml_pts:
                score = min(100, score + ml_pts)
                new_reasons.append(ml_reason)
            if linked_user:
                # preserve evidence-backed identity linkage for clustering
                new_reasons.append(f"+identity-link {linked_user}")
            conn.execute(
                "UPDATE detections SET risk_score = ?, reasons_json = ?,"
                " category = ? WHERE id = ?",
                (score, json.dumps(new_reasons),
                 normalize_category(r["category"]), r["id"]))
            # Detection classification is derivable deterministically from
            # score+severity+category (see classifier.classify_detection).


def _ev_iocs(ev: dict) -> list[dict]:
    """IOCs referenced inside an evidence entry are re-derived cheaply:
    evidence excerpts carry IPs/hashes; treat ipv4-ish tokens as 0.99."""
    import re
    txt = ev.get("excerpt", "") or ""
    out = []
    for m in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", txt):
        out.append({"value": m, "confidence": 0.99})
    return out


def _fetch_detections(job_id: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM detections WHERE job_id = ? ORDER BY id", (job_id,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json") or "[]")
        d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        out.append(d)
    return out


def _cluster_by_entity(dets: list[dict]) -> dict[str, list[dict]]:
    """Cluster detections sharing any entity value (ip or username)."""
    parent: dict[str, str] = {}

    def find(x):
        while parent.get(x, x) != x:
            x = parent[x] = parent.get(x, x)
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    keys = []
    success_links: list[tuple[str, str]] = []
    for d in dets:
        parts = [p for p in (d["entity"] or "").split(":") if p and p != "-"]
        keys.append(parts)
        for p in parts:
            parent.setdefault(p, p)
        for r in d["reasons"]:
            m = SUCCESS_NOTE_RX.search(r) or IDENTITY_LINK_RX.search(r)
            if m and parts:
                success_links.append((parts[0], m.group(1)))
    for parts in keys:
        for p in parts[1:]:
            union(parts[0], p)
    # Merge attacker-IP clusters with account clusters when a successful login
    # bridges them (evidence-backed identity linkage, not guesswork).
    for src_entity, user in success_links:
        union(src_entity, user)

    clusters: dict[str, list[dict]] = {}
    for d, parts in zip(dets, keys):
        if not parts:
            continue
        root = find(parts[0])
        clusters.setdefault(root, []).append(d)
    return clusters


# (primary_categories, follower_categories, combo_title, solo_title)
INCIDENT_TITLES = [
    (("brute force",),
     ("command execution", "malware", "privilege escalation"),
     "Possible Account Compromise", "Brute Force Attack"),
    (("port scanning",), (), "Reconnaissance / Port Scan Activity",
     "Reconnaissance / Port Scan Activity"),
    (("reconnaissance",), (), "Network Reconnaissance", "Network Reconnaissance"),
    (("web attack",), (), "Web Application Attack", "Web Application Attack"),
    (("command execution",), (), "Suspicious Command Execution",
     "Suspicious Command Execution"),
    (("malware",), (), "Malware-like Activity", "Malware-like Activity"),
    (("persistence",), (), "Persistence Mechanism Detected",
     "Persistence Mechanism Detected"),
]


def _title_for(categories: set[str]) -> str:
    cat_set = {c.lower() for c in categories}
    for primary, followers, combo, solo in INCIDENT_TITLES:
        if cat_set & set(primary):
            return combo if followers and (cat_set & set(followers)) else solo
    for _primary, followers, _combo, solo in INCIDENT_TITLES:
        if cat_set & set(followers):
            return solo
    return "Suspicious Activity Cluster"


def _build_one(job_id: str, entity: str, members: list[dict]) -> dict | None:
    member_ids = [m["id"] for m in members]
    categories = [normalize_category(m["category"]) for m in members]
    scores = [m["risk_score"] for m in members]
    success = any("successful authentication" in r.lower()
                  for m in members for r in m["reasons"])

    score, reasons = score_incident(scores, categories, success)
    classification = classify_incident(score, categories, success)
    title = _title_for(set(categories))

    timeline = sorted(
        (
            {"ts": e.get("ts") or "", "rule_id": m["rule_id"],
             "rule_name": m["rule_name"], "severity": m["severity"],
             "excerpt": e.get("excerpt", ""), "event_id": e.get("event_id")}
            for m in members for e in m["evidence"]
        ),
        key=lambda x: x["ts"] or "",
    )
    incident = {
        "job_id": job_id,
        "title": title,
        "category": ", ".join(sorted(set(categories))),
        "classification": classification,
        "severity": band(score),
        "entity": entity,
        "risk_score": score,
        "reasons": reasons,
        "event_ids": [e["event_id"] for e in timeline if e.get("event_id")][:200],
        "timeline": timeline[:200],
        "member_detection_ids": member_ids,
    }
    _insert_incident(incident)
    return incident


def _insert_incident(inc: dict) -> None:
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM correlations WHERE job_id = ? AND entity = ? AND title = ?",
            (inc["job_id"], inc["entity"], inc["title"])).fetchone()
        if existing:
            return
        conn.execute(
            "INSERT INTO correlations (job_id, title, category, classification,"
            " severity, entity, risk_score, reasons_json, evidence_event_ids_json,"
            " timeline_json, techniques_json, killchain_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (inc["job_id"], inc["title"], inc["category"], inc["classification"],
             inc["severity"], inc["entity"], inc["risk_score"],
             json.dumps(inc["reasons"]), json.dumps(inc["event_ids"]),
             json.dumps(inc["timeline"]), "[]", "{}"))


def _annotate_events(job_id: str, incidents: list[dict]) -> None:
    """Attribute threats to cited events (threat_type + risk contribution)."""
    with db() as conn:
        for inc in incidents:
            if not inc["event_ids"]:
                continue
            ph = ",".join("?" * len(inc["event_ids"]))
            primary_cat = inc["category"].split(",")[0].strip()
            conn.execute(
                f"UPDATE events SET threat_type = CASE WHEN threat_type = '' OR threat_type IS NULL"
                f" THEN ? ELSE threat_type END,"
                f" risk_score = MAX(risk_score, ?)"
                f" WHERE job_id = ? AND event_id IN ({ph})",
                (primary_cat, inc["risk_score"] // 2, job_id, *inc["event_ids"]),
            )
