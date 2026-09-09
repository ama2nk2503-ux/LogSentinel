from fastapi import APIRouter, HTTPException, Query

from core.storage import db
from normalization.schema import UniversalEvent

router = APIRouter()

ECS_OCSF_MAPPING = {
    "event_id": {"ecs": "event.id", "ocsf": "uid", "desc": "Unique event identifier"},
    "job_id": {"ecs": "event.dataset", "ocsf": "cloud.account.uid", "desc": "Processing job identifier"},
    "line_no": {"ecs": "event.line", "ocsf": "line_number", "desc": "Original line number in source"},
    "timestamp": {"ecs": "@timestamp", "ocsf": "time", "desc": "Event timestamp in ISO-8601 UTC"},
    "event_type": {"ecs": "event.action", "ocsf": "activity_name", "desc": "Normalized event category"},
    "source": {"ecs": "process.name", "ocsf": "actor.process.name", "desc": "Producing process/system name"},
    "source_ip": {"ecs": "source.ip", "ocsf": "src_endpoint.ip", "desc": "Source IP address"},
    "destination_ip": {"ecs": "destination.ip", "ocsf": "dst_endpoint.ip", "desc": "Destination IP address"},
    "source_port": {"ecs": "source.port", "ocsf": "src_endpoint.port", "desc": "Source port number"},
    "destination_port": {"ecs": "destination.port", "ocsf": "dst_endpoint.port", "desc": "Destination port number"},
    "protocol": {"ecs": "network.transport", "ocsf": "network.protocol", "desc": "Network protocol (TCP/UDP/ICMP)"},
    "username": {"ecs": "user.name", "ocsf": "actor.user.name", "desc": "Username involved in event"},
    "hostname": {"ecs": "host.name", "ocsf": "src_endpoint.hostname", "desc": "Hostname of source system"},
    "action": {"ecs": "event.outcome", "ocsf": "activity_id", "desc": "Action taken (allow/deny/failed/etc)"},
    "status": {"ecs": "event.result", "ocsf": "status", "desc": "Event status/result"},
    "severity": {"ecs": "event.severity", "ocsf": "severity", "desc": "Event severity level"},
    "message": {"ecs": "message", "ocsf": "description", "desc": "Human-readable event description"},
    "threat_type": {"ecs": "threat.technique.name", "ocsf": "category_name", "desc": "Classified threat category"},
    "risk_score": {"ecs": "event.risk_score", "ocsf": "risk_score", "desc": "Calculated risk score 0-100"},
    "iocs": {"ecs": "threat.indicator.*", "ocsf": "indicators", "desc": "Extracted indicators of compromise"},
    "pii_detected": {"ecs": "user.pii.*", "ocsf": "pii", "desc": "Detected PII types in event"},
    "redaction_status": {"ecs": "event.redaction", "ocsf": "redaction_status", "desc": "Privacy policy application status"},
    "anomaly_score": {"ecs": "ml.anomaly_score", "ocsf": "anomaly_score", "desc": "IsolationForest anomaly score 0-1"},
    "anomalous": {"ecs": "ml.is_anomalous", "ocsf": "is_anomalous", "desc": "Anomaly flag (threshold-based)"},
    "dedup_event_id": {"ecs": "event.dedup_id", "ocsf": "dedup_id", "desc": "Deterministic deduplication hash"},
    "timestamp_source": {"ecs": "event.timestamp_source", "ocsf": "timestamp_source", "desc": "Timestamp origin: event vs ingest"},
}


def _get_field_type(field_name: str) -> str:
    model_fields = UniversalEvent.model_fields
    if field_name in model_fields:
        annotation = model_fields[field_name].annotation
        return str(annotation).replace("typing.", "").replace("| None", "?").replace("list[", "array<").replace("dict", "object")
    return "unknown"


@router.get("/schema/docs/{job_id}")
def schema_docs(job_id: str):
    with db() as conn:
        job = conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        raise HTTPException(404, "Job not found")

    with db() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM events WHERE job_id = ?", (job_id,)).fetchone()["c"]
        if total == 0:
            coverage = {f: 0.0 for f in ECS_OCSF_MAPPING.keys()}
        else:
            SCALAR_COL = {
                "event_id": "event_id", "job_id": "job_id", "line_no": "line_no",
                "timestamp": "ts", "event_type": "event_type", "source": "source",
                "source_ip": "src_ip", "destination_ip": "dst_ip",
                "source_port": "src_port", "destination_port": "dst_port",
                "protocol": "protocol", "username": "username", "hostname": "hostname",
                "action": "action", "status": "status", "severity": "severity",
                "message": "message", "threat_type": "threat_type", "risk_score": "risk_score",
                "anomaly_score": "anomaly_score", "anomalous": "anomalous",
            }
            JSON_COL = {"iocs": "iocs_json", "pii_detected": "pii_json"}
            coverage = {}
            for field in ECS_OCSF_MAPPING.keys():
                col = SCALAR_COL.get(field)
                if col is not None:
                    non_null = conn.execute(
                        f"SELECT COUNT(*) c FROM events WHERE job_id = ? AND {col} IS NOT NULL AND {col} != ''",
                        (job_id,)
                    ).fetchone()["c"]
                elif field in JSON_COL:
                    # JSON list columns: populated when they hold a non-empty array
                    non_null = conn.execute(
                        f"SELECT COUNT(*) c FROM events WHERE job_id = ?"
                        f" AND {JSON_COL[field]} IS NOT NULL AND {JSON_COL[field]} NOT IN ('[]', 'null', '')",
                        (job_id,)
                    ).fetchone()["c"]
                else:
                    # Columns that may not exist yet (e.g. dedup_event_id, timestamp_source)
                    non_null = 0
                coverage[field] = round((non_null / total) * 100, 1)

    fields = []
    for field_name, mapping in ECS_OCSF_MAPPING.items():
        fields.append({
            "field": field_name,
            "type": _get_field_type(field_name),
            "ecs": mapping["ecs"],
            "ocsf": mapping["ocsf"],
            "coverage": coverage.get(field_name, 0.0),
            "description": mapping["desc"],
        })

    return {
        "job_id": job_id,
        "total_events": total,
        "fields": fields,
    }


@router.get("/schema/fields")
def schema_fields():
    fields = []
    for field_name, mapping in ECS_OCSF_MAPPING.items():
        fields.append({
            "field": field_name,
            "type": _get_field_type(field_name),
            "ecs": mapping["ecs"],
            "ocsf": mapping["ocsf"],
            "description": mapping["desc"],
        })
    return {"fields": fields}