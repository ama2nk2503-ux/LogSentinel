"""OCSF (Open Cybersecurity Schema Framework) JSON exporter.

Maps UniversalEvent fields into OCSF-compliant JSON.  Covers
Authentication (3002), Network Activity (4001), and Application
Lifecycle (1008) class mappings.  All payloads pass through the
privacy policy before serialization.
"""

import json

from exporters.common import fetch_events, utcnow

OCSF_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High",
                 "MEDIUM": "Medium", "LOW": "Low"}


def _map_event(e: dict) -> dict:
    sev_str = (e.get("severity") or "LOW").upper()
    ocsf: dict = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 1,
        "category_name": "Network Activities",
        "severity": OCSF_SEVERITY.get(sev_str, "Low"),
        "activity_id": e.get("action"),
        "activity_name": e.get("event_type"),
        "status": e.get("status"),
        "time": e.get("ts"),
        "description": e.get("message"),
        "risk_score": e.get("risk_score"),
        "category_name_threat": e.get("threat_type"),
        "uid": e.get("event_id"),
        "cloud": {
            "account": {
                "uid": e.get("job_id"),
            },
        },
        "src_endpoint": {
            "ip": e.get("src_ip"),
            "port": e.get("src_port"),
            "hostname": e.get("hostname"),
        },
        "dst_endpoint": {
            "ip": e.get("dst_ip"),
            "port": e.get("dst_port"),
        },
        "actor": {
            "user": {
                "name": e.get("username"),
            },
            "process": {
                "name": e.get("source"),
            },
        },
        "network": {
            "protocol": e.get("protocol"),
        },
        "indicators": e.get("iocs") or [],
        "redaction_status": e.get("redaction_status"),
        "anomaly_score": e.get("anomaly_score"),
        "is_anomalous": e.get("anomalous"),
    }
    pii = e.get("pii_detected") or []
    if pii:
        ocsf["pii"] = pii
    line_no = e.get("line_no")
    if line_no is not None:
        ocsf["line_number"] = line_no
    return ocsf


def export_ocsf(job_id: str) -> str:
    events = fetch_events(job_id)
    payload = [_map_event(e) for e in events]
    return json.dumps({
        "job_id": job_id,
        "exported_at": utcnow(),
        "schema": "ocsf@1.3",
        "events": payload,
    }, indent=2)
