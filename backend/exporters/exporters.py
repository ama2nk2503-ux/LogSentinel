"""SIEM-ready exporters: JSON / CSV / CEF / LEEF / STIX 2.1 / Syslog / ECS / OCSF.

All payloads pass through the privacy policy before serialization.
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone

from core.storage import db
from privacy.policy_engine import load_policy
from privacy.redactor import apply_policy
from exporters.ecs_export import export_ecs
from exporters.ocsf_export import export_ocsf

SEV_CEF = {"CRITICAL": "10", "HIGH": "8", "MEDIUM": "5", "LOW": "3"}
SEV_SYSLOG = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 5, "LOW": 7}   # RFC5424 severity

FIELDS = ["timestamp", "event_id", "event_type", "source", "source_ip",
          "destination_ip", "source_port", "destination_port", "protocol",
          "username", "hostname", "action", "status", "severity", "message",
          "threat_type", "risk_score"]


def fetch_events(job_id: str) -> list[dict]:
    policy = dict(load_policy())
    with db() as conn:
        rows = conn.execute(
            "SELECT e.*, j.filename AS _job_name FROM events e"
            " JOIN jobs j ON j.id = e.job_id WHERE e.job_id = ? ORDER BY e.id",
            (job_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["iocs"] = json.loads(d.pop("iocs_json") or "[]")
        d.pop("pii_json", None)
        d["pii_detected"] = json.loads(d.get("pii_json", "[]")) if "pii_json" in d else []
        msg, cats = apply_policy(d.get("message") or "", policy)
        d["message"], d["pii_detected"] = msg, sorted(set(d.get("pii_detected") or []) | set(cats))
        out.append(d)
    return out


def export_json(job_id: str) -> str:
    events = fetch_events(job_id)
    payload = [{
        "event_id": e.get("event_id"),
        "timestamp": e.get("ts"),
        "event_type": e.get("event_type"),
        "source": e.get("source"),
        "source_ip": e.get("src_ip"),
        "destination_ip": e.get("dst_ip"),
        "source_port": e.get("src_port"),
        "destination_port": e.get("dst_port"),
        "protocol": e.get("protocol"),
        "username": e.get("username"),
        "hostname": e.get("hostname"),
        "action": e.get("action"),
        "status": e.get("status"),
        "severity": e.get("severity"),
        "message": e.get("message"),
        "threat_type": e.get("threat_type"),
        "risk_score": e.get("risk_score"),
        "iocs": e.get("iocs") or [],
        "pii_detected": e.get("pii_detected") or [],
        "redaction_status": "applied",
    } for e in events]
    return json.dumps({"job_id": job_id,
                       "exported_at": _utcnow(),
                       "events": payload}, indent=2)


CSV_COLS = FIELDS


def export_csv(job_id: str) -> str:
    events = fetch_events(job_id)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(CSV_COLS)
    for e in events:
        w.writerow([e.get("ts"), e.get("event_id"), e.get("event_type"),
                    e.get("source"), e.get("src_ip"), e.get("dst_ip"),
                    e.get("src_port"), e.get("dst_port"), e.get("protocol"),
                    e.get("username"), e.get("hostname"), e.get("action"),
                    e.get("status"), e.get("severity"),
                    (e.get("message") or "").replace("\n", "\\n").replace("\r", ""),
                    e.get("threat_type"), e.get("risk_score")])
    return buf.getvalue()


def _cef_escape_ext(v: str) -> str:
    """Escape '=' '|' and newlines inside CEF extension values."""
    return (str(v).replace("\\", "\\\\").replace("=", "\\=")
            .replace("|", "\\|").replace("\n", "\\n").replace("\r", ""))


def export_cef(job_id: str) -> str:
    events = fetch_events(job_id)
    lines = []
    for e in events:
        sev = SEV_CEF.get((e.get("severity") or "LOW").upper(), "5")
        name = e.get("event_type") or "event"
        ext = {
            "src": e.get("src_ip"), "dst": e.get("dst_ip"),
            "spt": e.get("src_port"), "dpt": e.get("dst_port"),
            "proto": e.get("protocol"), "duser": e.get("username"),
            "shost": e.get("hostname"), "act": e.get("action"),
            "cs1": e.get("threat_type"), "cs1Label": "threat",
            "fname": None,
        }
        ext_str = " ".join(f"{k}={_cef_escape_ext(v)}" for k, v in ext.items() if v not in (None, ""))
        lines.append(
            f"CEF:0|LogSentinel|ThreatProcessor|1.0|{_cef_escape_ext(name)}|"
            f"{_cef_escape_ext(e.get('source') or name)}|{sev}|{ext_str} severity={sev}"
        )
    return "\n".join(lines)


def _leef_escape(v: str) -> str:
    return (str(v).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("=", "\\=").replace("\n", "\\n").replace("\r", ""))


def export_leef(job_id: str) -> str:
    events = fetch_events(job_id)
    lines = []
    for e in events:
        cat = e.get("severity") or "LOW"
        ident = f"{e.get('event_type')}|{_leef_escape(e.get('source') or 'unknown')}"
        attrs = "\t".join(
            f"{k}={_leef_escape(v)}" for k, v in {
                "src": e.get("src_ip"), "dst": e.get("dst_ip"),
                "proto": e.get("protocol"), "usrName": e.get("username"),
                "sev": cat, "identSrc": e.get("hostname"),
                "action": e.get("action"), "threat": e.get("threat_type"),
                "risk": e.get("risk_score"),
            }.items() if v not in (None, ""))
        lines.append(f"LEEF:1.0|LogSentinel|ThreatProcessor|1.0|{ident}\t{attrs}")
    return "\n".join(lines)


STIX_TYPE_MAP = {
    "ipv4": ("ipv4-addr", "value"),
    "ipv6": ("ipv6-addr", "value"),
    "domain": ("domain-name", "value"),
    "url": ("url", "value"),
    "md5": ("file", "hashes.'MD5'"),
    "sha1": ("file", "hashes.'SHA-1'"),
    "sha256": ("file", "hashes.'SHA-256'"),
}


def export_stix(job_id: str) -> str:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT json_extract(j.value,'$.value') value,
                   json_extract(j.value,'$.type') type,
                   MIN(e.ts) first_seen, MAX(e.ts) last_seen
            FROM events e, json_each(e.iocs_json) j
            WHERE e.job_id = ?
            GROUP BY value, type
            """,
            (job_id,),
        ).fetchall()

    objects = []
    ts = _utcnow()
    for r in rows:
        stix_type, prop_path = STIX_TYPE_MAP.get(r["type"])
        if not stix_type:
            continue
        pattern = f"[{stix_type}:{prop_path} = '{r['value']}']"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": r["first_seen"] or ts,
            "modified": r["last_seen"] or ts,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": r["first_seen"] or ts,
            "labels": ["logsentinel"],
        })
    return json.dumps({
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "timestamp": ts,
        "objects": objects,
    }, indent=2)


def export_syslog(job_id: str) -> str:
    events = fetch_events(job_id)
    lines = []
    for e in events:
        level = SEV_SYSLOG.get((e.get("severity") or "LOW").upper(), 6)
        pri = 4 * 8 + level                      # facility 4 = security/authorization
        ts = (e.get("ts") or _utcnow())[:19].replace("T", " ")
        host = (e.get("hostname") or "logsentinel").split()[0][:32]
        msg = (e.get("message") or "").replace("\n", " ").replace("\r", "")[:900]
        tag = e.get("source") or e.get("event_type") or "logsentinel"
        lines.append(f"<{pri}>{ts} {host} {tag}: {msg}")
    return "\n".join(lines)


EXPORTERS = {
    "json": export_json,
    "csv": export_csv,
    "cef": export_cef,
    "leef": export_leef,
    "stix": export_stix,
    "syslog": export_syslog,
    "ecs": export_ecs,
    "ocsf": export_ocsf,
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
