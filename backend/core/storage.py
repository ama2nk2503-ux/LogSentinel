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
    dedup_event_id TEXT DEFAULT '',
    timestamp_source TEXT DEFAULT 'ingest',
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
    created_at TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'NEW',
    assignee TEXT DEFAULT '',
    notes_json TEXT DEFAULT '[]',
    false_positive INTEGER DEFAULT 0,
    acknowledged_at TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_correlations_job ON correlations(job_id);

CREATE TABLE IF NOT EXISTS alert_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    source_type TEXT NOT NULL,
    severity TEXT DEFAULT 'MEDIUM',
    threshold INTEGER DEFAULT 1,
    match_rule_id TEXT,
    match_category TEXT,
    min_risk INTEGER DEFAULT 0,
    min_confidence REAL DEFAULT 0.0,
    dedup_window_minutes INTEGER DEFAULT 60,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    alert_rule_id TEXT NOT NULL,
    job_id TEXT DEFAULT '',
    source_type TEXT,
    source_id TEXT,
    entity TEXT DEFAULT '',
    entity_type TEXT DEFAULT '',
    severity TEXT,
    title TEXT NOT NULL,
    message TEXT DEFAULT '',
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'OPEN',
    dedup_key TEXT,
    metadata_json TEXT DEFAULT '{}',
    created_at TEXT,
    acknowledged_at TEXT,
    resolved_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS ix_alerts_rule ON alerts(alert_rule_id);
CREATE INDEX IF NOT EXISTS ix_alerts_job ON alerts(job_id);
CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts(dedup_key);

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

CREATE TABLE IF NOT EXISTS intel_reference (
    value TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    threat_type TEXT DEFAULT '',
    severity TEXT DEFAULT 'LOW',
    confidence REAL DEFAULT 0.0,
    source TEXT DEFAULT '',
    tags_json TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    name TEXT NOT NULL,
    entity_type TEXT DEFAULT '',
    asset_type TEXT DEFAULT 'unknown',
    criticality TEXT DEFAULT 'LOW',
    risk_score INTEGER DEFAULT 0,
    detections_count INTEGER DEFAULT 0,
    incidents_count INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    tags_json TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    UNIQUE (job_id, name)
);
CREATE INDEX IF NOT EXISTS ix_assets_job ON assets(job_id);

CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    status TEXT NOT NULL,
    summary_json TEXT DEFAULT '{}',
    findings_json TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit ON audits(job_id, framework);

CREATE TABLE IF NOT EXISTS ml_models (
    job_id TEXT PRIMARY KEY,
    params_json TEXT DEFAULT '{}',
    fitted_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS learned_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    template_key TEXT NOT NULL,
    template TEXT NOT NULL,
    mask_hash TEXT NOT NULL,
    line_count INTEGER DEFAULT 0,
    sample TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_learned_templates_job ON learned_templates(job_id);

CREATE TABLE IF NOT EXISTS hash_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    batch_no INTEGER NOT NULL,
    batch_start_id INTEGER,
    batch_end_id INTEGER,
    events_count INTEGER DEFAULT 0,
    batch_hash TEXT NOT NULL,
    prev_hash TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_hash_chain ON hash_chain(job_id, batch_no);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS baseline_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity TEXT NOT NULL,
    attribute TEXT NOT NULL,
    n INTEGER DEFAULT 0,
    mean REAL DEFAULT 0,
    m2 REAL DEFAULT 0,
    last_value REAL,
    last_seen TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE (entity_type, entity, attribute)
);
CREATE INDEX IF NOT EXISTS ix_baseline_entity ON baseline_stats(entity_type, entity);

CREATE TABLE IF NOT EXISTS baseline_jobs (
    job_id TEXT PRIMARY KEY,
    folded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS actions_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    action_id TEXT NOT NULL,
    action_label TEXT NOT NULL,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'SIMULATED — no live integration configured',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_actions_log_incident ON actions_log(incident_id);
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


# Columns added after the original schema shipped — ALTERed onto pre-existing
# databases so upgrades are additive (never destructive).
_COLUMN_MIGRATIONS = [
    ("correlations", "status", "TEXT DEFAULT 'NEW'"),
    ("correlations", "assignee", "TEXT DEFAULT ''"),
    ("correlations", "notes_json", "TEXT DEFAULT '[]'"),
    ("correlations", "false_positive", "INTEGER DEFAULT 0"),
    ("correlations", "acknowledged_at", "TEXT"),
    ("correlations", "resolved_at", "TEXT"),
    ("alert_rules", "asset_type", "TEXT"),
    ("alert_rules", "min_criticality", "TEXT"),
    ("events", "anomaly_score", "REAL DEFAULT 0"),
    ("events", "anomalous", "INTEGER DEFAULT 0"),
    ("events", "dedup_event_id", "TEXT DEFAULT ''"),
    ("events", "timestamp_source", "TEXT DEFAULT 'ingest'"),
    # M5 RBAC: role tiers viewer < analyst < admin. Default 'analyst' keeps
    # pre-existing accounts (registered before this milestone) on the analyst
    # tier; the seeded admin account is explicitly 'admin'.
    ("users", "role", "TEXT DEFAULT 'analyst'"),
]


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, decl in _COLUMN_MIGRATIONS:
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    # Index on a migrated column: must be created AFTER the ALTER above so
    # pre-existing databases (without dedup_event_id) upgrade cleanly.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_events_dedup ON events(job_id, dedup_event_id)")


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        # M5 Item 6: FTS5 free-text index (feature-detected — absent runtimes
        # keep the LIKE fallback; DDL is a no-op when unavailable).
        from core.fts import ensure as ensure_fts
        ensure_fts(conn)
    # M4: backfill deterministic ids for rows ingested before the column
    # existed (idempotent — recomputing yields the same hash).
    from core.dedup_backfill import backfill_dedup_ids
    backfill_dedup_ids()
