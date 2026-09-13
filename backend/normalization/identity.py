"""Deterministic, idempotent event identity (dedup ID).

The ID is a pure SHA-256 hash of (timestamp|hostname|process|raw_text) so the
same source line always maps to the same identity — re-ingesting a file never
creates new identities. When no timestamp is parseable, a constant marker is
hashed in place of the timestamp so ids stay stable and collision-safe.
"""

import hashlib

NO_TS_MARKER = "NOTS"

# Matches the raw_lines.raw cap so a backfill that re-reads stored raw text
# derives the identical hash as the original inline computation.
RAW_CAP = 8000


def deterministic_event_id(timestamp: str, hostname: str, process: str,
                           raw_text: str) -> str:
    ts = (timestamp or "").strip() or NO_TS_MARKER
    payload = "|".join((
        ts,
        (hostname or "").strip(),
        (process or "").strip(),
        (raw_text or "")[:RAW_CAP],
    ))
    return hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()[:32]
