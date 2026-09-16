"""SQLite FTS5 free-text search support (M5 Item 6).

The FTS5 index is kept in sync through the SAME batch-insert transaction used
by pipeline.py / simulator.py, so there is no separate write path that could
drift out of sync. When the runtime SQLite library has no FTS5 the feature is
detected (never assumed) and callers fall back to the original LIKE scan.
When at-rest encryption is enabled (M5 Item 8) the index is disabled too:
encrypted message bytes are useless to tokenize, and searches fall back to
the LIKE scan on the ciphertext exactly like the pre-FTS behavior.
"""

import sqlite3
import threading

from core.crypto import enabled
from core.storage import get_conn

FTS_TABLE = "events_fts"

_FTS_DDL = (
    f"CREATE VIRTUAL TABLE IF NOT EXISTS {FTS_TABLE} USING fts5("
    "message, raw_text, tokenize='unicode61')"
)

_fts_available: bool | None = None
_guard = threading.Lock()


def available(conn: sqlite3.Connection | None = None) -> bool:
    """True iff FTS5 is usable here AND at-rest encryption is off (memoized)."""
    if enabled():
        return False
    global _fts_available
    if _fts_available is not None:
        return _fts_available
    with _guard:
        if _fts_available is not None:
            return _fts_available
        try:
            c = conn or get_conn()
            c.execute(_FTS_DDL)
            _fts_available = True
        except sqlite3.OperationalError:
            _fts_available = False
    return _fts_available


def ensure(conn: sqlite3.Connection) -> None:
    """Create the FTS table on any connection when the feature exists."""
    if available(conn):
        conn.execute(_FTS_DDL)


def matcher(q: str) -> str:
    """Wrap a user query as a literal FTS5 phrase (special chars sanitized)."""
    return '"' + q.replace('"', " ").strip() + '"'


def index_batch(conn: sqlite3.Connection, job_id: str,
                min_line: int, max_line: int) -> None:
    """Index the events written in the current batch (same transaction).

    Sources message from `events` and the raw line from `raw_lines`, paired by
    (job_id, line_no) exactly like the rest of the pipeline.
    """
    conn.execute(
        f"INSERT INTO {FTS_TABLE}(rowid, message, raw_text) "
        "SELECT e.id, e.message, COALESCE(r.raw, e.message) "
        "FROM events e "
        "LEFT JOIN raw_lines r ON r.job_id = e.job_id AND r.line_no = e.line_no "
        "WHERE e.job_id = ? AND e.line_no BETWEEN ? AND ?",
        (job_id, min_line, max_line))