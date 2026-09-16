"""Per-entity online baseline with Welford online mean/variance.

Each processed job is one observation window. For every entity found in the
job we fold per-window aggregate values (event_count, risk_sum, unique
peer counts, ...) into a running Welford accumulator stored in
``baseline_stats``. Anomaly detection is a z-score against that running
baseline and always carries a human-readable reason string, so scores never
magically appear without context.
"""

import math
import sqlite3

from core.storage import db

EPS = 1e-9

# entity_type -> aggregate attributes we track
ATTRIBUTES: dict[str, list[str]] = {
    "ip": ["event_count", "risk_sum", "unique_dst_ips", "unique_dst_ports"],
    "hostname": ["event_count"],
    "username": ["event_count", "failed_logins"],
    "dst_port": ["event_count"],
}

# (entity_type, event column to group by, [(attribute, SQL aggregation), ...])
_JOB_AGG_SQL = [
    ("ip", "src_ip", [
        ("event_count", "COUNT(*)"),
        ("risk_sum", "COALESCE(SUM(risk_score), 0)"),
        ("unique_dst_ips", "COUNT(DISTINCT dst_ip)"),
        ("unique_dst_ports", "COUNT(DISTINCT dst_port)"),
    ]),
    ("dst_port", "dst_port", [("event_count", "COUNT(*)")]),
    ("hostname", "hostname", [("event_count", "COUNT(*)")]),
    ("username", "username", [
        ("event_count", "COUNT(*)"),
        ("failed_logins", "COALESCE(SUM(CASE WHEN LOWER(status) LIKE '%fail%' "
                           "OR LOWER(status) LIKE '%den%' OR LOWER(status) LIKE '%reject%' "
                           "OR LOWER(status) LIKE '%block%' THEN 1 ELSE 0 END), 0)"),
    ]),
]

_FALLBACK_REASONS = {
    "event_count": "event volume",
    "risk_sum": "aggregate risk",
    "unique_dst_ips": "unique destination IPs",
    "unique_dst_ports": "unique destination ports",
    "failed_logins": "failed logins",
}


def job_aggregates(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    """Aggregate per-entity values for one job (one baseline window)."""
    rows: list[dict] = []
    for et, col, attrs in _JOB_AGG_SQL:
        select_exprs = ", ".join(f"{sql} AS [{attr}]" for attr, sql in attrs)
        stmt = (
            f"SELECT {col} AS entity, {select_exprs} FROM events "
            f"WHERE job_id = ? AND {col} IS NOT NULL AND {col} != '' "
            f"GROUP BY {col}"
        )
        for r in conn.execute(stmt, (job_id,)):
            base = {"entity_type": et, "entity": str(r["entity"])}
            for attr, _ in attrs:
                base[attr] = r[attr]
            rows.append(base)
    return rows


def _fold(conn, entity_type: str, entity: str, attribute: str, x: float) -> None:
    row = conn.execute(
        "SELECT n, mean, m2 FROM baseline_stats WHERE entity_type = ? AND entity = ? AND attribute = ?",
        (entity_type, entity, attribute),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO baseline_stats (entity_type, entity, attribute, n, mean, m2, last_value, last_seen) "
            "VALUES (?, ?, ?, 1, ?, 0, ?, datetime('now'))",
            (entity_type, entity, attribute, float(x), float(x)),
        )
        return
    n, mean, m2 = row["n"], row["mean"], row["m2"]
    n1 = n + 1
    delta = x - mean
    mean1 = mean + delta / n1
    delta2 = x - mean1
    m2_1 = m2 + delta * delta2
    conn.execute(
        "UPDATE baseline_stats SET n = ?, mean = ?, m2 = ?, last_value = ?, "
        "last_seen = datetime('now'), updated_at = datetime('now') "
        "WHERE entity_type = ? AND entity = ? AND attribute = ?",
        (n1, mean1, m2_1, float(x), entity_type, entity, attribute),
    )


def fold_job(job_id: str) -> dict:
    """Fold a completed job's aggregates into the running baseline (idempotent)."""
    with db() as conn:
        already = conn.execute(
            "SELECT 1 FROM baseline_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if already is not None:
            return {"job_id": job_id, "folded": False, "reason": "already folded"}
        aggs = job_aggregates(conn, job_id)
        for a in aggs:
            for attr in ATTRIBUTES.get(a["entity_type"], []):
                _fold(conn, a["entity_type"], a["entity"], attr, float(a.get(attr) or 0))
        conn.execute("INSERT INTO baseline_jobs (job_id) VALUES (?)", (job_id,))
        return {
            "job_id": job_id,
            "folded": True,
            "windows": 1,
            "attributes": sum(len(ATTRIBUTES[a["entity_type"]]) for a in aggs),
        }


def rebuild_baseline(reset: bool = False) -> dict:
    """Re-fold every completed job. reset=True clears the baseline first."""
    with db() as conn:
        if reset:
            conn.execute("DELETE FROM baseline_jobs")
            conn.execute("DELETE FROM baseline_stats")
        job_ids = [
            r["id"]
            for r in conn.execute(
                "SELECT id FROM jobs WHERE status = 'done' ORDER BY created_at, id"
            ).fetchall()
        ]
    folded = skipped = 0
    for j in job_ids:
        res = fold_job(j)
        folded += int(res["folded"])
        skipped += int(not res["folded"])
    return {"folded_jobs": folded, "skipped_jobs": skipped, "reset": reset}


def list_baseline(entity_type: str | None = None, entity: str | None = None,
                  limit: int = 100, offset: int = 0) -> dict:
    with db() as conn:
        where, params = [], []
        if entity_type:
            where.append("entity_type = ?")
            params.append(entity_type)
        if entity:
            where.append("entity = ?")
            params.append(entity)
        clause = " WHERE " + " AND ".join(where) if where else ""
        rows = conn.execute(
            f"SELECT entity_type, entity, attribute, n, mean, m2, last_value, last_seen "
            f"FROM baseline_stats {clause} ORDER BY n DESC, mean DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) c FROM baseline_stats {clause}", params
        ).fetchone()["c"]
    stats = []
    for r in rows:
        std = math.sqrt(r["m2"] / r["n"]) if r["n"] > 1 else 0.0
        stats.append({
            "entity_type": r["entity_type"],
            "entity": r["entity"],
            "attribute": r["attribute"],
            "n": r["n"],
            "mean": round(r["mean"], 4),
            "std": round(std, 4),
            "cv": round(std / r["mean"], 4) if r["mean"] else 0.0,
            "last_value": r["last_value"],
            "last_seen": r["last_seen"],
        })
    return {"total": total, "stats": stats}


def job_anomalies(job_id: str, top: int = 20, min_z: float = 2.0) -> dict:
    """Compare one job's aggregates against the stored baseline (z >= min_z)."""
    with db() as conn:
        aggs = job_aggregates(conn, job_id)
        baseline: dict[tuple, tuple] = {}
        for r in conn.execute(
            "SELECT entity_type, entity, attribute, n, mean, m2 FROM baseline_stats"
        ).fetchall():
            baseline[(r["entity_type"], r["entity"], r["attribute"])] = (r["n"], r["mean"], r["m2"])
        windows = conn.execute("SELECT COUNT(*) c FROM baseline_jobs").fetchone()["c"]

    anomalies = []
    for a in aggs:
        et, entity = a["entity_type"], a["entity"]
        for attr in ATTRIBUTES.get(et, []):
            x = float(a.get(attr) or 0)
            spot = baseline.get((et, entity, attr))
            if spot is None:
                continue
            n, mean, m2 = spot
            if n < 2:
                continue
            std = math.sqrt(m2 / n)
            if std < EPS:
                continue
            z = (x - mean) / std
            if z < min_z:
                continue
            label = _FALLBACK_REASONS.get(attr, attr)
            anomalies.append({
                "entity_type": et,
                "entity": entity,
                "attribute": attr,
                "value": round(x, 4),
                "mean": round(mean, 4),
                "std": round(std, 4),
                "z": round(z, 3),
                "n": n,
                "reason": (
                    f"{label} for {et} {entity!r} is {x:g} "
                    f"({z:+.2f}\u03c3 vs baseline mean {mean:g} over {n} windows)"
                ),
            })
    anomalies.sort(key=lambda r: -r["z"])
    return {
        "job_id": job_id,
        "windows": windows,
        "total": len(anomalies),
        "anomalies": anomalies[:top],
    }