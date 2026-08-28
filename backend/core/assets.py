"""Deterministic asset inventory.

Assets are derived from a job's events: hostnames and source IPs become
assets, classified by role (web/database/network/server/...), scored by
risk, and tagged with the services/ports they expose. Per-asset alert rules
(alert_rules.yaml) gate their alerts on the asset's type and criticality.
"""

import json

from core.storage import db

SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "web", 110: "pop3", 143: "imap", 161: "snmp", 443: "web",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 8080: "web", 8443: "web", 9200: "elasticsearch",
}

NETWORK_SOURCES = {"firewall", "switch", "router", "asa", "iis"}

CRITICALITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _classify(hostname: str, services: set[str], sources: set[str]) -> str:
    if services & {"mysql", "postgres", "mssql", "mongodb"}:
        return "database"
    if services & {"web"}:
        return "web"
    if hostname or services:
        return "server"
    if sources & NETWORK_SOURCES:
        return "network"
    return "unknown"


def _base_criticality(asset_type: str) -> str:
    return {
        "database": "HIGH", "web": "HIGH", "network": "MEDIUM",
        "server": "MEDIUM", "unknown": "LOW",
    }.get(asset_type, "LOW")


def _bump(criticality: str, risk: int) -> str:
    if risk >= 75:
        return "CRITICAL"
    if risk >= 50:
        return max(CRITICALITY_ORDER, key=CRITICALITY_ORDER.get)[0] if criticality == "CRITICAL" else {
            "LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"
        }[criticality]
    return criticality


def build_assets(job_id: str) -> list[dict]:
    """Derive + persist assets for a job; returns the asset list."""
    acc: dict[str, dict] = {}
    with db() as conn:
        rows = conn.execute(
            "SELECT src_ip, dst_ip, hostname, source, dst_port, src_port, ts,"
            " risk_score FROM events WHERE job_id = ?", (job_id,)).fetchall()
        intervals = {"start": None, "end": None}
        counts = conn.execute(
            "SELECT entity, entity_type, COUNT(*) c, MAX(risk_score) r"
            " FROM detections WHERE job_id = ? GROUP BY entity, entity_type",
            (job_id,)).fetchall()
        inc_counts = conn.execute(
            "SELECT entity, COUNT(*) c FROM correlations WHERE job_id = ? GROUP BY entity",
            (job_id,)).fetchall()

    def key(name, etype):
        return (etype, (name or "").strip().lower())

    def asset_key(name, etype):
        norm = {"src_ip": "ip", "dst_ip": "ip", "ipv4": "ip", "hostname": "host"}.get(etype, etype)
        return key(name, norm)

    for r in rows:
        host = (r["hostname"] or "").strip()
        ip = (r["src_ip"] or "").strip()
        dst_ip = (r["dst_ip"] or "").strip()
        dst_port = r["dst_port"]
        ts = r["ts"] or ""
        names = []
        if host:
            names.append((host, "host"))
        elif ip:
            names.append((ip, "ip"))
        if dst_ip and dst_port in SERVICE_PORTS:
            names.append((dst_ip, "ip"))
        if not names:
            continue
        for nm, etype in names:
            a = acc.setdefault(key(nm, etype), {"name": nm, "entity_type": etype,
                "services": set(), "sources": set(), "src_ports": set(), "dst_ports": set(),
                "first_seen": None, "last_seen": None, "max_risk": 0})
            if r["dst_port"] and r["dst_port"] in SERVICE_PORTS:
                a["services"].add(SERVICE_PORTS[r["dst_port"]])
            if r["src_port"]:
                a["src_ports"].add(r["src_port"])
            if r["dst_port"]:
                a["dst_ports"].add(r["dst_port"])
            if r["source"]:
                a["sources"].add((r["source"] or "").strip())
            a["max_risk"] = max(a["max_risk"], int(r["risk_score"] or 0))
            if ts:
                if a["first_seen"] is None or ts < a["first_seen"]:
                    a["first_seen"] = ts
                if a["last_seen"] is None or ts > a["last_seen"]:
                    a["last_seen"] = ts

    det_map: dict[tuple, int] = {}
    for d in counts:
        det_map[asset_key(d["entity"], d["entity_type"])] = int(d["c"])
    inc_map: dict[str, int] = {}
    for i in inc_counts:
        inc_map[(i["entity"] or "").strip().lower()] = int(i["c"])

    assets = []
    for (etype, lname), a in acc.items():
        asset_type = _classify(a["name"], a["services"], a["sources"])
        criticality = _bump(_base_criticality(asset_type), a["max_risk"])
        dets = det_map.get((etype, lname), 0)
        incs = inc_map.get(lname, 0)
        tags = sorted(a["services"]) + (["exposed"] if a["dst_ports"] else [])
        assets.append({
            "job_id": job_id,
            "name": a["name"],
            "entity_type": etype,
            "asset_type": asset_type,
            "criticality": criticality,
            "risk_score": a["max_risk"],
            "detections_count": dets,
            "incidents_count": incs,
            "first_seen": a["first_seen"],
            "last_seen": a["last_seen"],
            "tags": tags,
            "metadata": {
                "services": sorted(a["services"]),
                "sources": sorted(s for s in a["sources"] if s),
                "src_ports": sorted(a["src_ports"])[:50],
                "dst_ports": sorted(a["dst_ports"])[:50],
            },
        })
    assets.sort(key=lambda a: (CRITICALITY_ORDER.get(a["criticality"], 0), a["risk_score"]), reverse=True)

    with db() as conn:
        conn.execute("DELETE FROM assets WHERE job_id = ?", (job_id,))
        conn.executemany(
            "INSERT INTO assets (job_id, name, entity_type, asset_type, criticality,"
            " risk_score, detections_count, incidents_count, first_seen, last_seen,"
            " tags_json, metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(a["job_id"], a["name"], a["entity_type"], a["asset_type"], a["criticality"],
              a["risk_score"], a["detections_count"], a["incidents_count"],
              a["first_seen"], a["last_seen"], json.dumps(a["tags"]),
              json.dumps(a["metadata"])) for a in assets])
    return assets


def list_assets(job_id: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE job_id = ? ORDER BY risk_score DESC, name", (job_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d.pop("tags_json") or "[]")
        d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
        out.append(d)
    return out


def asset_of(name: str) -> dict | None:
    """Highest-criticality asset for an entity name (latest job wins)."""
    with db() as conn:
        row = conn.execute(
            "SELECT a.* FROM assets a JOIN (SELECT name, MAX(id) t FROM assets"
            " GROUP BY name) latest ON latest.name = a.name AND latest.t = a.id"
            " WHERE lower(a.name) = ? ORDER BY a.risk_score DESC LIMIT 1",
            ((name or "").strip().lower(),)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["tags"] = json.loads(d.pop("tags_json") or "[]")
    d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
    return d