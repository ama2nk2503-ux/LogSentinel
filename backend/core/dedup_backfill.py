"""M4 backfill: compute deterministic dedup ids + timestamp_source for events
ingested before the columns existed. Idempotent — recomputing yields the same
hash, so running it any number of times is safe. Never touches event_id.
"""

from core.storage import db
from normalization.identity import deterministic_event_id

BATCH = 2000

# raw text is joined back from raw_lines by (job_id, line_no); events without
# a raw_lines row fall back to the stored message.
_SQL = (
    "SELECT e.id, e.job_id, e.line_no, e.ts, e.hostname, e.source, e.message,"
    " r.raw AS raw_line"
    " FROM events e LEFT JOIN raw_lines r"
    " ON r.job_id = e.job_id AND r.line_no = e.line_no"
    " WHERE e.dedup_event_id = '' OR e.dedup_event_id IS NULL"
    " LIMIT ?"
)

_UPDATE = (
    "UPDATE events SET dedup_event_id = ?, timestamp_source = ? WHERE id = ?"
)


def backfill_dedup_ids(batch_size: int = BATCH) -> int:
    """Fill in dedup_event_id/timestamp_source where missing. Returns row count."""
    updated = 0
    while True:
        with db() as conn:
            rows = conn.execute(_SQL, (batch_size,)).fetchall()
            if not rows:
                break
            for r in rows:
                from core.crypto import decrypt_text
                raw = (decrypt_text(r["raw_line"])
                       or decrypt_text(r["message"]) or "")
                # timestamp_source="event" iff a parseable ts produced e.ts;
                # rows whose ts is empty were ingested with the ingest-time
                # fallback (NO_TS_MARKER keeps their identity stable).
                ts_source = "event" if r["ts"] else "ingest"
                ts_for_hash = r["ts"] or ""
                dedup = deterministic_event_id(
                    ts_for_hash, r["hostname"], r["source"], raw)
                conn.execute(_UPDATE, (dedup, ts_source, r["id"]))
                updated += 1
    return updated


if __name__ == "__main__":
    n = backfill_dedup_ids()
    print(f"backfilled {n} events")
