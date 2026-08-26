"""YAML-driven detection engine: windowed, grouped evaluation over persisted events."""

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import yaml

from core.config import settings
from core.storage import db

RULE_FILES = ["authentication.yaml", "network.yaml", "web_attacks.yaml", "malware.yaml"]

# canonical event columns usable in `match:` / `group_by:`
COLUMN_ALIASES = {
    "source_ip": "src_ip", "destination_ip": "dst_ip",
    "destination_port": "dst_port", "source_port": "src_port",
    "username": "username", "event_type": "event_type", "status": "status",
    "action": "action", "protocol": "protocol", "hostname": "hostname",
    "event_id": "event_id", "severity": "severity",
}


@lru_cache(maxsize=1)
def load_rules() -> list[dict]:
    rules: list[dict] = []
    for name in RULE_FILES:
        path = settings.rules_dir / name
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for raw in data.get("rules", []):
            rule = _normalize_rule(raw)
            if rule:
                rules.append(rule)
    return rules


def reload_rules() -> int:
    load_rules.cache_clear()
    return len(load_rules())


def _normalize_rule(raw: dict) -> dict | None:
    try:
        rule = {
            "rule_id": str(raw["rule_id"]),
            "name": str(raw.get("name", raw["rule_id"])),
            "description": str(raw.get("description", "")),
            "category": str(raw.get("category", "Unknown")),
            "severity": str(raw.get("severity", "MEDIUM")).upper(),
            "match": {COLUMN_ALIASES[k]: v for k, v in (raw.get("match") or {}).items()
                      if k in COLUMN_ALIASES},
            "statuses": [str(s).lower() for s in raw.get("statuses", [])],
            "event_types": [str(t).lower() for t in raw.get("event_types", [])],
            "regex": re.compile(raw["regex"], re.I) if raw.get("regex") else None,
            "group_by": [COLUMN_ALIASES[g] for g in raw.get("group_by", ["src_ip"])
                         if g in COLUMN_ALIASES],
            "metric": str(raw.get("metric", "count")).lower(),
            "distinct_field": COLUMN_ALIASES.get(raw.get("distinct_field", ""), None),
            "threshold": int(raw.get("threshold", 1)),
            "window": _parse_window(str(raw.get("window", "5m"))),
            "then_success": bool(raw.get("then_success", False)),
        }
        if not rule["group_by"]:
            rule["group_by"] = ["src_ip"]
        return rule
    except (KeyError, ValueError, re.error):
        return None


def _parse_window(spec: str) -> timedelta:
    unit = spec[-1]
    qty = int(spec[:-1])
    return {"s": timedelta(seconds=qty), "m": timedelta(minutes=qty),
            "h": timedelta(hours=qty), "d": timedelta(days=qty)}[unit]


def _parse_ts(ts: str | None) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def evaluate_job(job_id: str) -> list[dict]:
    """Run all rules against one job's events. Returns created detections."""
    created: list[dict] = []
    with db() as conn:
        existing = {r["rule_id"] + "|" + (r["entity"] or "")
                    for r in map(dict, conn.execute(
                        "SELECT rule_id, entity FROM detections WHERE job_id = ?",
                        (job_id,)).fetchall())}
    for rule in load_rules():
        groups = _collect_groups(rule, job_id)
        for key, events in groups.items():
            hit = _evaluate_group(rule, events)
            if not hit:
                continue
            dedup_key = rule["rule_id"] + "|" + key
            if dedup_key in existing:
                continue
            evidence, window_start, window_end, metric_value = hit
            success_note = None
            if rule["then_success"] and hit[2] is not None:
                success_note = _check_success_followup(rule, job_id, key,
                                                       hit[2])
            reasons = [
                f"+{min(30, 10 + 4 * metric_value)} "
                f"{metric_value} matching events for '{rule['name']}' "
                f"(threshold {rule['threshold']}, window {rule['window']})"
            ]
            if success_note:
                reasons.append(f"+ successful authentication followed ({success_note})")
            det = {
                "job_id": job_id,
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "category": rule["category"],
                "entity": key,
                "entity_type": "->".join(rule["group_by"]),
                "evidence_json": evidence,
                "reasons_json": reasons,
                "risk_score": 0,   # P6 risk engine fills this
            }
            _insert_detection(det)
            created.append(det)
    return created


def _collect_groups(rule: dict, job_id: str) -> dict[str, list[dict]]:
    where = ["job_id = ?"]
    params: list = [job_id]
    for col, val in rule["match"].items():
        where.append(f"{col} = ?")
        params.append(val)
    if rule["statuses"]:
        where.append(f"LOWER(COALESCE(status,'')) IN ({','.join('?' * len(rule['statuses']))})")
        params.extend(rule["statuses"])
    if rule["event_types"]:
        where.append(f"LOWER(COALESCE(event_type,'')) IN ({','.join('?' * len(rule['event_types']))})")
        params.extend(rule["event_types"])

    with db() as conn:
        rows = conn.execute(
            f"SELECT id, event_id, ts, event_type, src_ip, dst_ip, src_port, dst_port,"
            f" username, hostname, status, severity, message FROM events"
            f" WHERE {' AND '.join(where)} ORDER BY ts",
            params,
        ).fetchall()

    if rule["regex"] is not None:
        rows = [r for r in rows if rule["regex"].search(r["message"] or "")]

    groups: dict[str, list[dict]] = {}
    gcols = rule["group_by"] or ["src_ip"]
    for r in rows:
        parts = [str(r[c]) if r[c] not in (None, "") else "-" for c in gcols]
        key = ":".join(parts)
        if key != "-" and any(p != "-" for p in parts):
            groups.setdefault(key, []).append(dict(r))
    return groups


def _evaluate_group(rule: dict, events: list[dict]):
    """Sliding-window check. Returns (evidence, start, end, value) or None.

    Timestamp-less sources (KV firewalls) fall back to whole-group evaluation.
    """
    def metric_value(seg):
        if rule["metric"] == "distinct":
            vals = {(e.get(rule["distinct_field"] or "dst_port")) for e in seg}
            return len(vals - {None})
        return len(seg)

    timed = sorted((e for e in events if e.get("ts")), key=lambda e: e["ts"])
    if not timed:
        if len(events) >= rule["threshold"]:
            val = metric_value(events)
            if val >= rule["threshold"]:
                evidence = [
                    {"event_id": e["event_id"], "ts": None,
                     "excerpt": (e.get("message") or "")[:160]}
                    for e in events[:50]
                ]
                return evidence, None, None, val
        return None
    if len(timed) < rule["threshold"]:
        return None
    win = rule["window"]
    best = None
    n = len(timed)
    left = 0
    for right in range(n):
        t_r = _parse_ts(timed[right]["ts"])
        while left <= right and t_r - _parse_ts(timed[left]["ts"]) > win:
            left += 1
        seg = timed[left:right + 1]
        val = metric_value(seg)
        if val >= rule["threshold"] and (best is None or val > best[3]):
            best = (seg, timed[left]["ts"], timed[right]["ts"], val)
    if best is None:
        return None
    seg, start, end, val = best
    evidence = [
        {"event_id": e["event_id"], "ts": e["ts"],
         "excerpt": (e.get("message") or "")[:160]}
        for e in seg[:50]
    ]
    return evidence, start, end, val


def _check_success_followup(rule: dict, job_id: str, key: str, after_ts: str) -> str | None:
    src_val = key.split(":")[0]
    with db() as conn:
        row = conn.execute(
            "SELECT ts, username FROM events WHERE job_id = ? AND event_type = 'auth_success'"
            " AND src_ip = ? AND ts >= ? ORDER BY ts LIMIT 1",
            (job_id, src_val, after_ts),
        ).fetchone()
    if row:
        return f"{row['username'] or src_val}@{row['ts']}"
    return None


def _insert_detection(det: dict) -> None:
    import json
    with db() as conn:
        conn.execute(
            "INSERT INTO detections (job_id, rule_id, rule_name, severity, category,"
            " entity, entity_type, evidence_json, techniques_json, reasons_json, risk_score)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (det["job_id"], det["rule_id"], det["rule_name"], det["severity"],
             det["category"], det["entity"], det["entity_type"],
             json.dumps(det["evidence_json"]), "[]",
             json.dumps(det["reasons_json"]), det["risk_score"]),
        )
