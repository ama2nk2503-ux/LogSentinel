"""In-loop ML anomaly scoring.

A seeded IsolationForest is fit per job on a deterministic numeric feature
vector (see ml.features). Each event gets an anomaly_score in [0, 1] and an
`anomalous` flag; detections whose evidence is anomalous then receive a risk
bump with an explainable reason line (see core.ml.bump). The model is never
served from the network — training is local and reproducible for identical
input (random_state + single-threaded fit).
"""

import json
import threading

from sklearn.ensemble import IsolationForest   # type: ignore[import-untyped]
from sklearn.preprocessing import LabelEncoder  # type: ignore[import-untyped]

from core.storage import db
from ml.features import CAT_COLUMNS, FEATURE_NAMES, extract_features

N_ESTIMATORS = 100
CONTAMINATION = 0.05
THRESHOLD = 0.7
MAX_TRAIN_EVENTS = 5000
MIN_EVENTS = 8

_lock = threading.Lock()
# per-job fitted artifacts to score live stream events without a DB round-trip
_cache: dict[str, dict] = {}


def _load_rows(job_id: str, limit: int | None = None) -> list[tuple[int, dict]]:
    sql = (
        "SELECT id, ts, event_type, status, protocol, src_port, dst_port,"
        " severity, risk_score, message, iocs_json, pii_json, extras_json"
        " FROM events WHERE job_id = ? ORDER BY id"
    )
    params: list = [job_id]
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    with db() as conn:
        rows = list(conn.execute(sql, params))
    from core.crypto import decrypt_text
    out = []
    for r in rows:
        d = dict(r)
        d["message"] = decrypt_text(d.get("message"))
        out.append((int(r[0]), d))
    return out


def _encode_cats(rows: dict):
    cat_map: dict[str, dict[str, int]] = {}
    for col in CAT_COLUMNS:
        values = sorted({str(r.get(col) or "") for _, r in rows})
        le = LabelEncoder().fit(values)
        cat_map[col] = dict(zip(le.classes_.tolist(), le.transform(le.classes_).tolist()))
    return cat_map


def _per_feature_stats(rows: list[dict], X: list[list[float]],
                       raw: list[dict]) -> tuple[dict, dict]:
    """Mean/std per feature over the training matrix + modal raw values.

    Computed from the SAME matrix the IsolationForest was fit on, so
    explanations (ml.explain) are consistent with the trained model.
    """
    n = len(X)
    dim = len(FEATURE_NAMES)
    sums = [0.0] * dim
    sumsq = [0.0] * dim
    for x in X:
        for i in range(dim):
            sums[i] += x[i]
            sumsq[i] += x[i] * x[i]
    stats, typical = {}, {}
    for i, name in enumerate(FEATURE_NAMES):
        mean = sums[i] / n if n else 0.0
        var = max(0.0, sumsq[i] / n - mean * mean)
        stats[name] = {"mean": round(mean, 4), "std": round(var ** 0.5, 4)}
    # Modal raw values for display ("typical 80" for dst_port, etc.).
    from collections import Counter
    for name in ("src_port", "dst_port"):
        vals = [r.get(name) for r in raw if r.get(name) not in (None, "", -1)]
        if vals:
            typical[name] = Counter(vals).most_common(1)[0][0]
    for col in CAT_COLUMNS:
        vals = [r.get(col, "") or "" for r in raw]
        if vals:
            typical[col] = Counter(vals).most_common(1)[0][0]
    return stats, typical


def train_job(job_id: str) -> dict:
    """Fit the anomaly model on a job's events, persist scores, return stats."""
    rows = _load_rows(job_id, MAX_TRAIN_EVENTS)
    stats = {"job_id": job_id, "model": f"IsolationForest@{N_ESTIMATORS}",
             "features": FEATURE_NAMES, "contamination": CONTAMINATION,
             "threshold": THRESHOLD, "n_events": len(rows), "trained": False,
             "n_anomalies": 0}
    if len(rows) < MIN_EVENTS:
        _persist(job_id, stats)
        return stats

    cat_map = _encode_cats(rows)
    X = [extract_features(r, cat_map) for _, r in rows]
    feature_stats, feature_typical = _per_feature_stats(rows, X,
                                                        [r for _, r in rows])
    model = IsolationForest(
        n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
        random_state=42, n_jobs=1,
    )
    model.fit(X)

    decision = model.decision_function(X)
    lo, hi = float(decision.min()), float(decision.max())
    scale = hi - lo
    scores = []
    for d in decision:
        s = 0.0 if scale < 1e-9 else min(1.0, max(0.0, (hi - float(d)) / scale))
        scores.append(round(s, 4))
    anomalous = [1 if s >= THRESHOLD else 0 for s in scores]

    with db() as conn:
        for (event_id, _row), s, flag in zip(rows, scores, anomalous):
            conn.execute(
                "UPDATE events SET anomaly_score = ?, anomalous = ? WHERE id = ?",
                (s, flag, event_id),
            )
    stats.update(trained=True, n_anomalies=sum(anomalous),
                 min_s=lo, max_s=hi,
                 feature_stats=feature_stats, feature_typical=feature_typical)
    _persist(job_id, stats)
    with _lock:
        _cache[job_id] = {"model": model, "cat_map": cat_map,
                          "lo": lo, "hi": hi, "n_events": len(rows),
                          "feature_stats": feature_stats,
                          "feature_typical": feature_typical}
    return stats


def refresh(job_id: str, force: bool = False) -> dict:
    """Retrain for streaming jobs when new events arrived since last fit."""
    with _lock:
        cached = _cache.get(job_id)
    if not force and cached and _count(job_id) == cached.get("n_events"):
        stats = _meta(job_id)
        return stats or {"job_id": job_id, "trained": True}
    return train_job(job_id)


def score_event(job_id: str, row: dict) -> float:
    """Score a single live event against the cached job model (0.0 if none)."""
    with _lock:
        cache = _cache.get(job_id)
    if not cache:
        return 0.0
    x = extract_features(row, cache["cat_map"])
    d = float(cache["model"].decision_function([x])[0])
    scale = cache["hi"] - cache["lo"]
    if scale < 1e-9:
        return 0.0
    return round(min(1.0, max(0.0, (cache["hi"] - d) / scale)), 4)


def _count(job_id: str) -> int:
    with db() as conn:
        return int(conn.execute(
            "SELECT COUNT(*) FROM events WHERE job_id = ?", (job_id,)).fetchone()[0])


def _persist(job_id: str, stats: dict) -> None:
    payload = {k: v for k, v in stats.items() if k not in ("job_id",)}
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ml_models (job_id, params_json, fitted_at)"
            " VALUES (?, ?, datetime('now'))",
            (job_id, json.dumps(payload)),
        )


def _meta(job_id: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT params_json FROM ml_models WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        return None
    meta = json.loads(row["params_json"])
    meta["job_id"] = job_id
    return meta


def bump(evidence: list[dict], job_id: str) -> tuple[int, str]:
    """ML risk contribution for a detection's evidence events.

    Returns (points, reason). Escalation is driven by the peak anomaly score
    of the evidence events (a single shock event is the classic anomaly
    signal); a reason line keeps the escalation explainable. The summary line
    is never replaced — a per-feature detail (ml.explain) is APPENDED so the
    story stays expandable without changing the existing sentence.
    """
    ids = [str(e.get("event_id")) for e in evidence if e.get("event_id")]
    if not ids:
        return 0, ""
    ph = ",".join("?" * len(ids))
    with db() as conn:
        rows = conn.execute(
            f"SELECT id, event_id, ts, event_type, status, protocol,"
            f" src_port, dst_port, severity, risk_score, message,"
            f" iocs_json, pii_json, extras_json,"
            f" anomaly_score, anomalous FROM events"
            f" WHERE job_id = ? AND event_id IN ({ph})",
            (job_id, *ids),
        ).fetchall()
    if not rows:
        return 0, ""
    from core.crypto import decrypt_text
    rows = [dict(r) for r in rows]
    for r in rows:
        r["message"] = decrypt_text(r.get("message"))
    scores = [r["anomaly_score"] or 0 for r in rows]
    flagged = sum(1 for r in rows if r["anomalous"])
    peak = max(scores)
    if flagged < 1 or peak < (THRESHOLD - 0.15):
        return 0, ""
    pts = min(30, int(round(20 * peak)))
    if not pts:
        return 0, ""
    reason = (f"+{pts} ML anomaly signal ({flagged}/{len(rows)} evidence "
              f"events anomalous, peak score {peak:.2f})")
    # M5 Item 7: expandable top-feature breakdown for the peak anomalous
    # event (deterministic pick: highest score, then lowest event id).
    peak_rows = [r for r in rows if r["anomalous"]
                 and float(r["anomaly_score"] or 0) == peak]
    if peak_rows:
        peak_rows.sort(key=lambda r: int(r["id"]))
        from ml import explain as ml_explain
        detail = ml_explain.summary(job_id, dict(peak_rows[0]))
        if detail:
            reason += detail
    return pts, reason


def job_stats(job_id: str) -> dict:
    """Lightweight summary for jobs/dashboard without re-running the model."""
    with db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(anomalous),0) a"
            " FROM events WHERE job_id = ?", (job_id,)).fetchone()
    return {"n_events": row["n"], "n_anomalies": row["a"]}