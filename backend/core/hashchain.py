"""Chain-of-custody hash chain (M4, additive).

Per job, a SHA-256 chain is appended after each existing batch insert:
each batch's hash covers every event row in that batch, and links to the
previous batch's hash (prev_hash), so any post-hoc edit of stored evidence
breaks verification. Ingestion logic is untouched beyond the append call —
if hashing ever fails, ingestion continues (wrapped).
"""

import hashlib

from core.storage import db

GENESIS = ""


def _event_digest(row) -> str:
    """Deterministic per-event digest over tamper-evident fields."""
    from core.crypto import decrypt_text
    payload = "|".join(str(x if x is not None else "") for x in (
        row["event_id"], row["line_no"], row["ts"], row["src_ip"],
        row["dst_ip"], row["event_type"], row["severity"],
        decrypt_text(row["message"]),
    ))
    return hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()


def _batch_hash(conn, job_id: str, start_id: int, end_id: int) -> str:
    rows = conn.execute(
        "SELECT event_id, line_no, ts, src_ip, dst_ip, event_type, severity,"
        " message FROM events WHERE job_id = ? AND id >= ? AND id <= ?"
        " ORDER BY id", (job_id, start_id, end_id))
    h = hashlib.sha256()
    for row in rows:
        h.update(_event_digest(row).encode("ascii"))
    return h.hexdigest()


def append_batch(conn, job_id: str) -> None:
    """Extend the job's chain with a batch covering all events inserted since
    the previous link. MUST be called inside the same transaction/with-block
    as the batch insert. Never raises into the caller."""
    try:
        prev = conn.execute(
            "SELECT batch_no, batch_end_id, batch_hash FROM hash_chain"
            " WHERE job_id = ? ORDER BY batch_no DESC LIMIT 1", (job_id,)).fetchone()
        start = (prev["batch_end_id"] + 1) if prev else 1
        end_row = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM events WHERE job_id = ?",
            (job_id,)).fetchone()
        end = end_row[0]
        if end < start:
            return
        count = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE job_id = ? AND id >= ? AND id <= ?",
            (job_id, start, end)).fetchone()["c"]
        batch_hash = _batch_hash(conn, job_id, start, end)
        conn.execute(
            "INSERT OR REPLACE INTO hash_chain"
            " (job_id, batch_no, batch_start_id, batch_end_id, events_count,"
            "  batch_hash, prev_hash) VALUES (?,?,?,?,?,?,?)",
            (job_id, (prev["batch_no"] + 1) if prev else 1,
             start, end, count, batch_hash,
             prev["batch_hash"] if prev else GENESIS))
    except Exception:  # noqa: BLE001 — chain must never break ingestion
        pass


def verify_integrity(job_id: str) -> dict:
    """Recompute every batch hash and the chain linkage for a job."""
    with db() as conn:
        links = conn.execute(
            "SELECT batch_no, batch_start_id, batch_end_id, events_count,"
            " batch_hash, prev_hash FROM hash_chain WHERE job_id = ?"
            " ORDER BY batch_no", (job_id,)).fetchall()
        problems = []
        prev_hash = GENESIS
        for link in links:
            if link["prev_hash"] != prev_hash:
                problems.append({"batch_no": link["batch_no"],
                                 "issue": "prev_hash mismatch (chain broken)"})
            recomputed = _batch_hash(conn, job_id,
                                     link["batch_start_id"], link["batch_end_id"])
            if recomputed != link["batch_hash"]:
                problems.append({"batch_no": link["batch_no"],
                                 "issue": "batch hash mismatch (evidence altered)"})
            prev_hash = link["batch_hash"]
    return {
        "job_id": job_id,
        "valid": not problems,
        "batches": len(links),
        "events_covered": sum(l["events_count"] for l in links),
        "problems": problems,
    }
