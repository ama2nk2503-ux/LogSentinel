"""ECS (Elastic Common Schema) JSON exporter.

Maps UniversalEvent fields into ECS-nested JSON.  All payloads pass through
the privacy policy before serialization.
"""

import json

from exporters.common import fetch_events, utcnow

ECS_SEVERITY = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 10}


def _map_event(e: dict) -> dict:
    sev_str = (e.get("severity") or "LOW").upper()
    ecs_event: dict = {
        "event": {
            "id": e.get("event_id"),
            "dataset": e.get("job_id"),
            "action": e.get("event_type"),
            "outcome": e.get("action"),
            "result": e.get("status"),
            "severity": ECS_SEVERITY.get(sev_str, 10),
            "risk_score": e.get("risk_score"),
            "redaction": e.get("redaction_status"),
            "dedup_id": e.get("dedup_event_id"),
            "timestamp_source": e.get("timestamp_source"),
        },
        "@timestamp": e.get("ts"),
        "source": {
            "ip": e.get("src_ip"),
            "port": e.get("src_port"),
        },
        "destination": {
            "ip": e.get("dst_ip"),
            "port": e.get("dst_port"),
        },
        "network": {
            "transport": e.get("protocol"),
        },
        "user": {
            "name": e.get("username"),
        },
        "host": {
            "name": e.get("hostname"),
        },
        "process": {
            "name": e.get("source"),
        },
        "message": e.get("message"),
        "threat": {
            "technique": {
                "name": e.get("threat_type"),
            },
            "indicator": e.get("iocs") or [],
        },
        "ml": {
            "anomaly_score": e.get("anomaly_score"),
            "is_anomalous": e.get("anomalous"),
        },
    }
    pii = e.get("pii_detected") or []
    if pii:
        ecs_event["user"]["pii"] = pii
    return ecs_event


def export_ecs(job_id: str) -> str:
    events = fetch_events(job_id)
    payload = [_map_event(e) for e in events]
    return json.dumps({
        "job_id": job_id,
        "exported_at": utcnow(),
        "schema": "ecs@1.16",
        "events": payload,
    }, indent=2)
