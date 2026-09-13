"""Universal Event Schema — every parsed log maps into this shape."""

from typing import ClassVar

from pydantic import BaseModel, Field


class UniversalEvent(BaseModel):
    event_id: str = ""
    job_id: str = ""
    line_no: int | None = None
    timestamp: str = ""                 # ISO-8601 UTC
    event_type: str = "unclassified"
    source: str = ""                    # producing process/system (sshd, apache…)
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = ""
    username: str = ""
    hostname: str = ""
    action: str = ""
    status: str = ""
    message: str = ""
    severity: str = "LOW"
    iocs: list[dict] = Field(default_factory=list)
    threat_type: str = ""
    risk_score: int = 0
    dedup_event_id: str = ""          # deterministic idempotent identity (M4)
    timestamp_source: str = "ingest"   # "event" (parsed) vs "ingest" (fallback)
    pii_detected: list[str] = Field(default_factory=list)
    redaction_status: str = "not_applied"
    # --- internal enrichment (stripped from external responses when needed) ---
    mappings: dict = Field(default_factory=dict)   # raw->normalized provenance
    extras: dict = Field(default_factory=dict)

    SEVERITY_ORDER: ClassVar[list[str]] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def to_row(self) -> tuple:
        import json
        return (
            self.event_id or None, self.job_id, self.line_no, self.timestamp,
            self.event_type, self.source, self.source_ip, self.destination_ip,
            self.source_port, self.destination_port, self.protocol,
            self.username, self.hostname, self.action, self.status,
            self.severity, self.message, self.threat_type, self.risk_score,
            self.dedup_event_id, self.timestamp_source,
            json.dumps(self.iocs), json.dumps(self.pii_detected),
            json.dumps(self.mappings), "[]",
            json.dumps(self.extras),
        )