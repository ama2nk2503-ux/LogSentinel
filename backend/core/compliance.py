"""Deterministic compliance audit engine.

Evaluates static framework controls (rules/compliance.yaml) against a job's
stored facts. Each control runs a metric query; the result is PASS or FAIL
with an evidence count and a human note. Audits are persisted (audits table,
one row per job+framework) so history is trackable and reportable.
"""

import json

import yaml

from core.config import settings
from core.storage import db

COMPLIANCE_FILE = "compliance.yaml"

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _load() -> dict:
    path = settings.rules_dir / COMPLIANCE_FILE
    if not path.exists():
        return {"frameworks": []}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def list_frameworks() -> list[dict]:
    return _load().get("frameworks", [])


def _filters_clause(filters: dict | None, prefix: str = "") -> tuple[str, list]:
    where, params = [], []
    for key, val in (filters or {}).items():
        where.append(f"{prefix}{key} = ?")
        params.append(val)
    return (" AND " + " AND ".join(where)) if where else "", params


def _metric_count(job_id: str, metric: str, filters: dict | None) -> int:
    if metric == "event_count":
        clause, params = _filters_clause(filters, "e.")
        with db() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) c FROM events e WHERE e.job_id = ?{clause}", (job_id, *params)).fetchone()
        return row["c"]
    if metric == "detection_count":
        clause, params = _filters_clause(filters, "d.")
        with db() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) c FROM detections d WHERE d.job_id = ?{clause}", (job_id, *params)).fetchone()
        return row["c"]
    if metric == "incident_count":
        clause, params = _filters_clause(filters, "c.")
        with db() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) c FROM correlations c WHERE c.job_id = ?{clause}", (job_id, *params)).fetchone()
        return row["c"]
    if metric == "untriaged_incidents":
        with db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) c FROM correlations WHERE job_id = ? AND status = 'NEW'"
                " AND false_positive = 0", (job_id,)).fetchone()
        return row["c"]
    if metric == "pii_count":
        with db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE job_id = ? AND pii_json != '[]'", (job_id,)).fetchone()
        return row["c"]
    if metric == "risk_surface":
        with db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) c FROM (SELECT src_ip, COUNT(*) c FROM events"
                " WHERE job_id = ? AND risk_score >= 60 GROUP BY src_ip)", (job_id,)).fetchone()
        return row["c"]
    return 0


def _passes(operator: str, value: int, count: int) -> bool:
    if operator == "ge":
        return count >= value
    if operator == "gt":
        return count > value
    if operator == "eq":
        return count == value
    return count <= value  # 'le' — low count is the compliant posture


def _note(control: dict, count: int, passes: bool) -> str:
    default = f"metric={control['metric']} count={count}"
    if passes:
        return f"Compliant — {default}"
    return f"Non-compliant — {default}"


def audit_job(job_id: str) -> list[dict]:
    """Run every framework against the job; persist + return framework audit rows."""
    results = []
    for framework in list_frameworks():
        findings = []
        for control in framework.get("controls", []):
            count = _metric_count(job_id, control["metric"], control.get("filters"))
            passes = _passes(control.get("operator", "le"), int(control.get("value", 0)), count)
            findings.append({
                "control": control.get("id", ""),
                "title": control.get("title", ""),
                "description": control.get("description", ""),
                "severity": control.get("severity", "low"),
                "status": "PASS" if passes else "FAIL" if SEVERITY_WEIGHT[control.get("severity", "low")] >= 3 else "WARN",
                "count": count,
                "operator": control.get("operator", "le"),
                "value": int(control.get("value", 0)),
                "note": control.get("note", ""),
            })
        res = summarize(framework["name"], findings)
        _persist(job_id, res)
        results.append(res)
    return results


def summarize(framework_name: str, findings: list[dict]) -> dict:
    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    warned = sum(1 for f in findings if f["status"] == "WARN")
    if failed:
        status = "FAIL"
    elif warned:
        status = "WARN"
    elif passed:
        status = "PASS"
    else:
        status = "NONE"
    return {
        "framework": framework_name,
        "status": status,
        "passed": passed,
        "failed": failed,
        "warned": warned,
        "total": len(findings),
        "score": round((passed / max(1, len(findings))) * 100, 1),
        "findings": findings,
    }


def _persist(job_id: str, result: dict) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audits (job_id, framework, status, summary_json, findings_json)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(job_id, framework) DO UPDATE SET status=excluded.status,"
            " summary_json=excluded.summary_json, findings_json=excluded.findings_json,"
            " created_at=datetime('now')",
            (job_id, result["framework"], result["status"],
             json.dumps({k: result[k] for k in ("passed", "failed", "warned", "total", "score")}),
             json.dumps(result["findings"])))


def audit_history(job_id: str | None = None) -> list[dict]:
    with db() as conn:
        if job_id:
            rows = conn.execute(
                "SELECT * FROM audits WHERE job_id = ? ORDER BY created_at DESC", (job_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audits ORDER BY created_at DESC LIMIT 200").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["summary"] = json.loads(d.pop("summary_json") or "{}")
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
        out.append(d)
    return out


def render_report(job_id: str, framework_name: str) -> str:
    """Compose a deterministic compliance report (Markdown) from audit data."""
    rows = audit_history(job_id)
    audit = next((r for r in rows if r["framework"].lower() == framework_name.lower()), None)
    if audit is None:
        raise LookupError(f"No audit for framework '{framework_name}' on this job")
    lines = [
        f"# LogSentinel Compliance Report",
        "",
        f"**Framework:** {audit['framework']}  ",
        f"**Dataset:** `{job_id}`  ",
        f"**Status:** {audit['status']}  ",
        f"**Score:** {audit['summary'].get('score', 0)}/100  ",
        f"**Generated:** {audit['created_at']}  ",
        "",
        "## Findings",
        "",
        "| Control | Severity | Status | Count | Note |",
        "|---|---|---|---|---|",
    ]
    for f in audit["findings"]:
        lines.append(f"| {f['control']} {f['title']} | {f['severity']} | {f['status']} | {f['count']} | {f['note']} |")
    lines += [
        "",
        f"**Summary:** {audit['summary'].get('passed', 0)} passed, "
        f"{audit['summary'].get('failed', 0)} failed, "
        f"{audit['summary'].get('warned', 0)} warned.",
        "",
    ]
    return "\n".join(lines)