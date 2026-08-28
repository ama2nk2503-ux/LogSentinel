"""Aggregated dashboard statistics — every number computed from stored data."""

import json

from fastapi import APIRouter, HTTPException

from core.storage import db

router = APIRouter()


@router.get("/dashboard/{job_id}")
def dashboard(job_id: str):
    with db() as conn:
        job = conn.execute(
            "SELECT id, filename, status, stage, progress, detected_format,"
            " format_confidence, stats_json FROM jobs WHERE id = ?",
            (job_id,)).fetchone()
        if job is None:
            raise HTTPException(404, "Job not found")

        one = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731
        total = one("SELECT COUNT(*) FROM events WHERE job_id=?", job_id)
        incidents_total = one("SELECT COUNT(*) FROM correlations WHERE job_id=?", job_id)
        critical = one("SELECT COUNT(*) FROM correlations WHERE job_id=? AND severity='CRITICAL'", job_id)
        malicious = one("SELECT COUNT(*) FROM correlations WHERE job_id=? AND classification='MALICIOUS'", job_id)
        uniq_iocs = one("""
            SELECT COUNT(DISTINCT json_extract(j.value,'$.value')) FROM events e,
            json_each(e.iocs_json) j WHERE e.job_id=?""", job_id)
        pii_events = one(
            "SELECT COUNT(*) FROM events WHERE job_id=? AND pii_json != '[]'", job_id)
        detections_total = one("SELECT COUNT(*) FROM detections WHERE job_id=?", job_id)
        ml_anomalies = one(
            "SELECT COUNT(*) FROM events WHERE job_id=? AND anomalous=1", job_id)

        def group(sql):
            return [{"label": r[0] or "UNKNOWN", "count": r[1]}
                    for r in conn.execute(sql, (job_id,))]

        severity = group(
            "SELECT UPPER(COALESCE(severity,'LOW')) AS label, COUNT(*) AS n"
            " FROM events WHERE job_id=? GROUP BY label ORDER BY n DESC")
        types = group(
            "SELECT COALESCE(event_type,'unclassified') AS label, COUNT(*) AS n"
            " FROM events WHERE job_id=? GROUP BY label ORDER BY n DESC LIMIT 8")
        top_ips = group(
            "SELECT COALESCE(src_ip,'-') AS label, COUNT(*) AS n FROM events"
            " WHERE job_id=? AND src_ip IS NOT NULL GROUP BY label ORDER BY n DESC LIMIT 8")
        threat_types = group(
            "SELECT COALESCE(threat_type,'None') AS label, COUNT(*) AS n FROM events"
            " WHERE job_id=? AND threat_type != '' GROUP BY label ORDER BY n DESC LIMIT 8")
        timeline = [
            {"minute": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT strftime('%H:%M', ts) AS m, COUNT(*) AS n FROM events"
                " WHERE job_id=? AND ts IS NOT NULL GROUP BY m ORDER BY m", (job_id,))
        ]
        ioc_types = [
            {"label": r[0], "count": r[1]}
            for r in conn.execute(
                """
                SELECT json_extract(j.value,'$.type'), COUNT(*)
                FROM events e, json_each(e.iocs_json) j
                WHERE e.job_id=? GROUP BY 1 ORDER BY 2 DESC
                """, (job_id,))
        ]

    stats = json.loads(job["stats_json"] or "{}")
    return {
        "job": {
            "id": job["id"], "filename": job["filename"], "status": job["status"],
            "stage": job["stage"], "progress": job["progress"],
            "detected_format": job["detected_format"],
            "format_confidence": job["format_confidence"],
        },
        "cards": {
            "total_events": total,
            "normalized": stats.get("parsed_lines", total),
            "threats": incidents_total,
            "malicious": malicious,
            "critical": critical,
            "detections": detections_total,
            "iocs_unique": uniq_iocs,
            "pii_events": pii_events,
            "redacted": pii_events,   # gate applies policy to every output
            "ml_anomalies": ml_anomalies,
            "ml_model": stats.get("ml_trained", 0),
        },
        "charts": {
            "severity": severity,
            "event_types": types,
            "top_ips": top_ips,
            "threat_types": threat_types,
            "timeline": timeline,
            "ioc_types": ioc_types,
        },
    }
