"""SQLite storage layer. All queries MUST use parameterized statements."""

import sqlite3
import threading
from contextlib import contextmanager

from core.config import settings

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    source_type TEXT DEFAULT 'upload',
    status TEXT DEFAULT 'pending',
    progress REAL DEFAULT 0,
    stage TEXT DEFAULT 'uploaded',
    detected_format TEXT,
    format_confidence REAL,
    stats_json TEXT DEFAULT '{}',
    error TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS raw_lines (
    job_id TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    raw TEXT NOT NULL,
    PRIMARY KEY (job_id, line_no)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    job_id TEXT NOT NULL,
    line_no INTEGER,
    ts TEXT,
    event_type TEXT,
    source TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    username TEXT,
    hostname TEXT,
    action TEXT,
    status TEXT,
    severity TEXT DEFAULT 'LOW',
    message TEXT DEFAULT '',
    threat_type TEXT DEFAULT '',
    risk_score INTEGER DEFAULT 0,
    iocs_json TEXT DEFAULT '[]',
    pii_json TEXT DEFAULT '[]',
    mappings_json TEXT DEFAULT '{}',
    attack_json TEXT DEFAULT '[]',
    extras_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_events_job ON events(job_id);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_eventid ON events(event_id);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    category TEXT,
    entity TEXT,
    entity_type TEXT,
    evidence_json TEXT DEFAULT '[]',
    techniques_json TEXT DEFAULT '[]',
    reasons_json TEXT DEFAULT '[]',
    risk_score INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_detections_job ON detections(job_id);

CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    title TEXT,
    category TEXT,
    classification TEXT,
    severity TEXT,
    entity TEXT,
    risk_score INTEGER DEFAULT 0,
    reasons_json TEXT DEFAULT '[]',
    evidence_event_ids_json TEXT DEFAULT '[]',
    timeline_json TEXT DEFAULT '[]',
    techniques_json TEXT DEFAULT '[]',
    killchain_json TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_correlations_job ON correlations(job_id);

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    threat_type TEXT DEFAULT '',
    severity TEXT DEFAULT 'LOW',
    confidence REAL DEFAULT 0.0,
    first_seen TEXT,
    last_seen TEXT,
    related_events INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_indicator ON indicators(value, type);

CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT DEFAULT (datetime('now')),
    results_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
"""


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(settings.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
