"""Deterministic alerting engine.

Evaluates enabled alert rules over a job's facts (detections, incidents,
indicators) and persists alerts to SQLite. Deduplication is rule+entity scoped
with a configurable window so the same situation does not re-alert on replay,
while a genuinely NEW fact (fresh incident) still surfaces. Alerting is fully
deterministic and explainable — every alert lists the exact facts that fired it.
"""

import json
import smtplib
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import yaml

from core.config import settings
from core.jobs import new_id
from core.storage import db

ALERT_RULES_FILE = "alert_rules.yaml"

OPEN_STATUSES = ("OPEN", "ACKNOWLEDGED")
TERMINAL_STATUSES = ("RESOLVED", "FALSE_POSITIVE")

ALERT_STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_seed_rules() -> list[dict]:
    """Parse rules/alert_rules.yaml. Pure helper, no DB access."""
    path = settings.rules_dir / ALERT_RULES_FILE
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for raw in data.get("rules", []):
        if isinstance(raw, dict) and raw.get("rule_id"):
            out.append(_normalize_rule(raw))
    return out


def _normalize_rule(raw: dict) -> dict:
    return {
        "rule_id": str(raw["rule_id"]).strip(),
        "name": str(raw.get("name") or raw["rule_id"]).strip(),
        "description": str(raw.get("description", "")).strip(),
        "enabled": int(bool(raw.get("enabled", True))),
        "source_type": str(raw.get("source_type", "detection")).strip().lower(),
        "severity": str(raw.get("severity", "MEDIUM")).strip().upper(),
        "threshold": max(1, int(raw.get("threshold", 1))),
        "match_rule_id": (raw.get("match_rule_id") or "").strip() or None,
        "match_category": (raw.get("match_category") or "").strip() or None,
        "min_risk": max(0, int(raw.get("min_risk", 0))),
        "min_confidence": max(0.0, float(raw.get("min_confidence", 0.0))),
        "dedup_window_minutes": max(1, int(raw.get("dedup_window_minutes", 60))),
        "asset_type": (raw.get("asset_type") or "").strip().lower() or None,
        "min_criticality": (raw.get("min_criticality") or "").strip().upper() or None,
    }


_RULE_COLUMNS = (
    "rule_id", "name", "description", "enabled", "source_type", "severity",
    "threshold", "match_rule_id", "match_category", "min_risk",
    "min_confidence", "dedup_window_minutes", "asset_type", "min_criticality")


def _insert_rule(conn, rule: dict) -> None:
    conn.execute(
        f"INSERT INTO alert_rules ({', '.join(_RULE_COLUMNS)})"
        f" VALUES ({', '.join('?' * len(_RULE_COLUMNS))})",
        tuple(rule[c] for c in _RULE_COLUMNS))


def seed_alert_rules() -> int:
    """Seed the seed file only when the table is empty (startup, not a wipe)."""
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) c FROM alert_rules").fetchone()["c"]
        if count:
            return 0
        for rule in load_seed_rules():
            _insert_rule(conn, rule)
        return len(load_seed_rules()) if count == 0 else 0


def create_rule(rule: dict) -> dict:
    rule = _normalize_rule(rule)
    with db() as conn:
        existing = conn.execute(
            "SELECT 1 FROM alert_rules WHERE rule_id = ?", (rule["rule_id"],)).fetchone()
        if existing:
            raise ValueError(f"Alert rule '{rule['rule_id']}' already exists")
        _insert_rule(conn, rule)
    return rule


def update_rule(rule_id: str, patch: dict) -> dict | None:
    rule = _normalize_rule({**{"rule_id": rule_id, "name": rule_id}, **patch})
    with db() as conn:
        existing = conn.execute(
            "SELECT 1 FROM alert_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not existing:
            return None
        cols = ", ".join(f"{c} = ?" for c in _RULE_COLUMNS)
        conn.execute(f"UPDATE alert_rules SET {cols} WHERE rule_id = ?",
                     (*tuple(rule[c] for c in _RULE_COLUMNS), rule_id))
    return rule


def reload_alert_rules() -> int:
    """Reset the rule table from rules/alert_rules.yaml (admin reset action)."""
    rules = load_seed_rules()
    with db() as conn:
        conn.execute("DELETE FROM alert_rules")
        for rule in rules:
            _insert_rule(conn, rule)
    return len(rules)


def list_alert_rules() -> list[dict]:
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM alert_rules ORDER BY enabled DESC, rule_id").fetchall()]


def evaluate_alerts(job_id: str) -> list[dict]:
    """Run enabled alert rules against a job's facts; insert + return alerts."""
    with db() as conn:
        rules = [dict(r) for r in conn.execute(
            "SELECT * FROM alert_rules WHERE enabled = 1").fetchall()]
        if not rules:
            return []
        dets = [dict(r) for r in conn.execute(
            "SELECT id, rule_id, category, entity, severity, risk_score"
            " FROM detections WHERE job_id = ?", (job_id,)).fetchall()]
        incs = [dict(r) for r in conn.execute(
            "SELECT id, job_id, title, severity, entity, risk_score, category,"
            " evidence_event_ids_json FROM correlations WHERE job_id = ?", (job_id,)).fetchall()]

    # IOCs live in a persistent global watchlist (indicators table): high-
    # confidence indicators alert regardless of the originating job.
    with db() as conn:
        iocs = [dict(r) for r in conn.execute(
            "SELECT value, type, confidence, threat_type FROM indicators"
            " WHERE confidence > 0").fetchall()]

    created: list[dict] = []
    for rule in rules:
        for candidate in _candidates(rule, dets, incs, iocs):
            if _suppressed(rule, candidate["dedup_key"]):
                continue
            alert = _insert_alert(rule, candidate)
            if alert:
                created.append(alert)
    return created


def _candidates(rule: dict, dets: list[dict], incs: list[dict],
                iocs: list[dict]) -> list[dict]:
    """Turn rule + facts into alert candidates (post-dedup, pre-insert)."""
    st = rule["source_type"]
    if st == "detection":
        matched = [d for d in dets
                   if (not rule["match_rule_id"] or d["rule_id"] == rule["match_rule_id"])
                   and (not rule["match_category"]
                        or (d["category"] or "").lower() == rule["match_category"].lower())
                   and (d["risk_score"] or 0) >= rule["min_risk"]]
        return _grouped(rule, matched, "detection", entity_key=lambda d: d["entity"] or "-",
                        risk_fn=lambda d: d["risk_score"] or 0,
                        severity_fn=lambda d: d["severity"] or "MEDIUM",
                        title_fn=lambda d: rule["name"])
    if st == "incident":
        # Incident rules are gated on min_risk (severity is illustrative).
        # Per-asset rules additionally gate on the entity's role/criticality.
        out = []
        for i in incs:
            if (i["risk_score"] or 0) < rule["min_risk"]:
                continue
            if rule["asset_type"] or rule["min_criticality"]:
                assets = _assets_for(i)
                if not assets:
                    continue
                if rule["asset_type"] and not any(
                        a.get("asset_type") == rule["asset_type"] for a in assets):
                    continue
                if rule["min_criticality"] and not any(
                        _criticality_rank(a.get("criticality", "LOW")) >= _criticality_rank(rule["min_criticality"])
                        for a in assets):
                    continue
            out.append({
                "dedup_key": f"{rule['rule_id']}|{i['entity'] or '-'}|inc{i['id']}",
                "entity": i["entity"] or "-",
                "entity_type": "incident",
                "source_id": f"inc{i['id']}",
                "severity": i["severity"] or rule["severity"],
                "risk_score": i["risk_score"] or 0,
                "title": f"{rule['name']} — {i['title']}",
                "message": _incident_message(i),
                "metadata": {"incident_id": i["id"], "category": i["category"],
                             "job_id": job_id_of(i),
                             "count": 1},
            })
        return out
    if st == "ioc":
        matched = [x for x in iocs if (x["confidence"] or 0) >= rule["min_confidence"]]
        return _grouped(rule, matched, "ioc", entity_key=lambda x: x["value"],
                        risk_fn=lambda x: int((x["confidence"] or 0) * 100),
                        severity_fn=lambda x: x.get("threat_type") and "HIGH" or rule["severity"],
                        title_fn=lambda x: f"{rule['name']} — {x['value']}")
    return []


def job_id_of(i: dict) -> str:
    return i.get("job_id", "")


_CRITICALITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _criticality_rank(value: str) -> int:
    return _CRITICALITY_RANK.get((value or "").strip().upper(), 0)


def _assets_for(inc: dict) -> list[dict]:
    """Resolve the assets touched by an incident: its attacker entity plus any
    victim hosts referenced by its correlated evidence (dst-side services)."""
    from core.assets import asset_of
    from core.storage import db
    names: set[str] = {(inc.get("entity") or "").strip() if (inc.get("entity") or "").strip() != "-" else ""}
    evidence = inc.get("evidence_event_ids_json") or "[]"
    try:
        ids = json.loads(evidence)
    except (TypeError, ValueError):
        ids = []
    if isinstance(ids, list) and ids:
        ev_ids = [str(x) for x in ids if str(x).lstrip("-").isdigit() or str(x).strip()]
        if ev_ids:
            with db() as conn:
                rows = conn.execute(
                    "SELECT src_ip, dst_ip, hostname FROM events WHERE job_id = ? AND"
                    " event_id IN (%s)" % ",".join("?" * len(ev_ids)),
                    (inc.get("job_id"), *ev_ids)).fetchall()
            for r in rows:
                for val in (r["dst_ip"], r["src_ip"], r["hostname"]):
                    if val:
                        names.add((val or "").strip())
    names.discard("")
    out = []
    for n in names:
        a = asset_of(n)
        if a:
            out.append(a)
    return out


def _grouped(rule: dict, items: list[dict], source_type: str, *,
             entity_key, risk_fn, severity_fn, title_fn) -> list[dict]:
    """Aggregate per-entity counts; fire when the count crosses threshold."""
    by_entity: dict[str, list[dict]] = {}
    for it in items:
        by_entity.setdefault(entity_key(it) or "-", []).append(it)
    out = []
    for entity, group in by_entity.items():
        if len(group) < rule["threshold"]:
            continue
        top = max(group, key=lambda x: risk_fn(x) or 0)
        out.append({
            "dedup_key": f"{rule['rule_id']}|{entity}",
            "entity": entity,
            "entity_type": source_type,
            "source_id": None,
            "severity": severity_fn(top),
            "risk_score": risk_fn(top) or 0,
            "title": title_fn(top),
            "message": _grouped_message(rule, entity, len(group)),
            "metadata": {"count": len(group)},
        })
    return out


def _incident_message(inc: dict) -> str:
    return (f"{inc['title']} · {inc['category']} · "
            f"risk {inc['risk_score']}/100 · entity {inc['entity'] or '-'}")


def _grouped_message(rule: dict, entity: str, count: int) -> str:
    return (f"{count} matching evidence fact(s) for '{rule['name']}' "
            f"under entity {entity} (threshold {rule['threshold']})")


def _suppressed(rule: dict, dedup_key: str) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=rule["dedup_window_minutes"])).isoformat()
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE dedup_key = ?"
            " AND (status IN ('OPEN', 'ACKNOWLEDGED') OR created_at >= ?) LIMIT 1",
            (dedup_key, cutoff)).fetchone()
    return row is not None


def _insert_alert(rule: dict, cand: dict) -> dict | None:
    alert = {
        "id": new_id(),
        "alert_rule_id": rule["rule_id"],
        "job_id": cand.get("job_id", ""),
        "source_type": rule["source_type"],
        "source_id": cand.get("source_id"),
        "entity": cand["entity"],
        "entity_type": cand.get("entity_type", ""),
        "severity": cand["severity"],
        "title": cand["title"],
        "message": cand["message"],
        "risk_score": cand["risk_score"],
        "status": "OPEN",
        "dedup_key": cand["dedup_key"],
        "metadata_json": json.dumps(cand.get("metadata", {})),
        "created_at": _now(),
    }
    with db() as conn:
        conn.execute(
            "INSERT INTO alerts (id, alert_rule_id, job_id, source_type, source_id,"
            " entity, entity_type, severity, title, message, risk_score, status,"
            " dedup_key, metadata_json, created_at, acknowledged_at, resolved_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (alert["id"], alert["alert_rule_id"], alert["job_id"], alert["source_type"],
             alert["source_id"], alert["entity"], alert["entity_type"], alert["severity"],
             alert["title"], alert["message"], alert["risk_score"], alert["status"],
             alert["dedup_key"], alert["metadata_json"], alert["created_at"], None, None,
             alert["created_at"]))
    return {**alert, "metadata": cand.get("metadata", {})}


def list_alerts(status: str | None = None, severity: str | None = None,
                rule_id: str | None = None, limit: int = 100) -> list[dict]:
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity = ?")
        params.append(severity.upper())
    if rule_id:
        where.append("alert_rule_id = ?")
        params.append(rule_id)
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(500, limit)))
    with db() as conn:
        return [_row(r) for r in conn.execute(sql, params).fetchall()]


def get_alert(alert_id: str) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row(row) if row else None


def _row(r) -> dict:
    d = dict(r)
    d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
    return d


def _transition(alert_id: str, status: str, fp: bool = False) -> dict | None:
    now = _now()
    with db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ?,"
            " resolved_at = CASE WHEN ? IN ('RESOLVED','FALSE_POSITIVE') THEN ? ELSE resolved_at END,"
            " acknowledged_at = CASE WHEN ? = 'ACKNOWLEDGED' AND acknowledged_at IS NULL THEN ? ELSE acknowledged_at END"
            " WHERE id = ?",
            (status, now, status, now, status, now, alert_id))
        if fp:
            _fp_risk_feedback(row)
    return get_alert(alert_id)


def ack(alert_id: str) -> dict | None:
    return _transition(alert_id, "ACKNOWLEDGED")


def resolve(alert_id: str) -> dict | None:
    return _transition(alert_id, "RESOLVED")


def false_positive(alert_id: str) -> dict | None:
    return _transition(alert_id, "FALSE_POSITIVE", fp=True)


def post_notify(alert_id: str) -> dict:
    """Deliver an alert to configured channels (webhook/email). Config-free
    channels are skipped; at least one must be configured to deliver."""
    alert = get_alert(alert_id)
    if alert is None:
        raise LookupError("Alert not found")
    payload = {
        "alert_id": alert["id"],
        "title": alert["title"],
        "severity": alert["severity"],
        "status": alert["status"],
        "entity": alert["entity"],
        "rule": alert["alert_rule_id"],
        "risk_score": alert["risk_score"],
        "message": alert["message"],
        "created_at": alert["created_at"],
    }
    channels: list[str] = []
    if settings.webhook_url:
        req = urllib.request.Request(
            settings.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10):  # noqa: S310 — admin-configured webhook
            channels.append("webhook")
    if settings.smtp_host:
        msg = EmailMessage()
        msg["Subject"] = f"[LogSentinel {payload['severity']}] {payload['title']}"
        msg["From"] = settings.smtp_from
        msg["To"] = settings.smtp_to
        msg.set_content(
            f"{payload['message']}\n\nRule: {payload['rule']}\nEntity: "
            f"{payload['entity']}\nRisk: {payload['risk_score']}/100\n"
            f"Fired: {payload['created_at']}")
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as srv:
            srv.starttls()
            if settings.smtp_user:
                srv.login(settings.smtp_user, settings.smtp_password)
            srv.send_message(msg)
        channels.append("email")
    if not channels:
        return {"delivered": False, "channels": [],
                "reason": "no notifier configured — set LOGSENTINEL_WEBHOOK_URL or LOGSENTINEL_SMTP_*"}
    return {"delivered": True, "channels": channels}


def _fp_risk_feedback(row) -> None:
    """False-positive feedback: suppress the source's risk so tuning learns.

    Incident sources are downgraded in place (labelled as triaged false
    positive); detection sources get their alert-scoped risk halved so
    re-correlation shows the analyst's verdict.
    """
    source_id = row["source_id"]
    if not source_id or row["source_type"] not in ("incident", "detection"):
        return
    if source_id.startswith("inc"):
        inc_id = source_id[3:]
        with db() as conn:
            cur = conn.execute(
                "SELECT risk_score, reasons_json FROM correlations WHERE id = ?",
                (inc_id,)).fetchone()
            if cur:
                reasons = json.loads(cur["reasons_json"] or "[]")
                if not any("false-positive" in r for r in reasons):
                    reasons.append("+ false-positive feedback: risk suppressed by analyst")
                conn.execute(
                    "UPDATE correlations SET risk_score = MAX(1, ?), false_positive = 1,"
                    " status = 'FALSE_POSITIVE', resolved_at = ?, reasons_json = ? WHERE id = ?",
                    (max(1, (cur["risk_score"] or 0) // 2), _now(),
                     json.dumps(reasons), inc_id))