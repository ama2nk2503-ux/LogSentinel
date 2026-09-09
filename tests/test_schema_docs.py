"""Schema Docs endpoint tests — direct DB seeding + function calls (existing pytest style).

Endpoint: GET /api/schema/docs/{job_id}  -> schema_docs(job_id)
           GET /api/schema/fields       -> schema_fields()
"""

import pytest
from fastapi import HTTPException

from api.routes_schema import schema_docs, schema_fields, _get_field_type
from core.storage import db
from tests.test_detection import insert_event


def _seed_job(job_id: str, n: int = 4) -> None:
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO jobs (id, filename, status) VALUES (?, ?, 'done')",
            (job_id, f"{job_id}.log"),
        )
    for i in range(n):
        insert_event(job_id, ts=f"2026-08-25T10:0{i}:00Z", event_type="auth_failure",
                     src_ip="185.23.45.67", username="admin", status="failure",
                     message=f"Failed password for admin #{i}")


def test_schema_fields_returns_full_mapping():
    result = schema_fields()
    assert "fields" in result
    fields = {f["field"] for f in result["fields"]}
    for required in ("event_id", "timestamp", "source_ip", "destination_ip",
                     "severity", "message", "threat_type", "risk_score", "iocs"):
        assert required in fields
    for f in result["fields"]:
        assert all(k in f for k in ("field", "type", "ecs", "ocsf", "description"))


def test_schema_docs_job_not_found():
    with pytest.raises(HTTPException) as exc:
        schema_docs("does-not-exist")
    assert exc.value.status_code == 404


def test_schema_docs_coverage_with_seeded_events():
    job_id = "t_schema_docs"
    _seed_job(job_id, n=4)
    result = schema_docs(job_id)
    assert result["job_id"] == job_id
    assert result["total_events"] == 4

    field_map = {f["field"]: f for f in result["fields"]}
    # event-provided fields should be fully covered on a seeded job
    assert field_map["timestamp"]["coverage"] == 100.0
    assert field_map["source_ip"]["coverage"] == 100.0
    assert field_map["event_id"]["coverage"] == 100.0
    # fields never populated stay 0
    assert field_map["destination_ip"]["coverage"] == 0.0
    assert field_map["anomaly_score"]["coverage"] >= 0.0


def test_schema_docs_ecs_ocsf_mappings():
    result = schema_fields()
    field_map = {f["field"]: f for f in result["fields"]}
    assert field_map["timestamp"]["ecs"] == "@timestamp"
    assert field_map["timestamp"]["ocsf"] == "time"
    assert field_map["source_ip"]["ecs"] == "source.ip"
    assert field_map["source_ip"]["ocsf"] == "src_endpoint.ip"
    assert field_map["event_id"]["ecs"] == "event.id"
    assert field_map["event_id"]["ocsf"] == "uid"


def test_field_type_resolution():
    assert "str" in _get_field_type("timestamp")
    assert "int" in _get_field_type("risk_score")
    assert "array" in _get_field_type("iocs") or "list" in _get_field_type("iocs")