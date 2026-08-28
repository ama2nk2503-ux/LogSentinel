"""ML anomaly-scoring API: model metadata + top anomalous events per job."""

import json

from fastapi import APIRouter, HTTPException

from core.storage import db

router = APIRouter()


@router.get("/ml/{job_id}")
def ml_job(job_id: str):
    with db() as conn:
        job = conn.execute(
            "SELECT id, filename FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if job is None:
            raise HTTPException(404, "Job not found")
        model = conn.execute(
            "SELECT params_json, fitted_at FROM ml_models WHERE job_id = ?",
            (job_id,)).fetchone()
        summary = conn.execute(
            "SELECT COUNT(*) n, COALESCE(SUM(anomalous),0) a"
            " FROM events WHERE job_id = ?", (job_id,)).fetchone()
        anomalies = [
            {
                "event_id": r["event_id"], "ts": r["ts"],
                "src_ip": r["src_ip"], "dst_ip": r["dst_ip"],
                "event_type": r["event_type"], "severity": r["severity"],
                "message": (r["message"] or "")[:200],
                "anomaly_score": r["anomaly_score"],
            }
            for r in conn.execute(
                "SELECT event_id, ts, src_ip, dst_ip, event_type, severity,"
                " message, anomaly_score FROM events WHERE job_id = ?"
                " AND anomalous = 1 ORDER BY anomaly_score DESC LIMIT 20",
                (job_id,))
        ]
    meta = json.loads(model["params_json"] or "{}") if model else None
    return {
        "job_id": job_id,
        "trained": bool(meta and meta.get("trained")),
        "model": meta,
        "fitted_at": model["fitted_at"] if model else None,
        "summary": {"n_events": summary["n"], "n_anomalies": summary["a"]},
        "anomalies": anomalies,
    }