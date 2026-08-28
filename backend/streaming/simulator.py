"""Controlled real-time stream simulation feeding the same pipeline."""

import asyncio
import random
from datetime import datetime, timezone

from core import jobs
from core.alerts import evaluate_alerts
from core.storage import db
from detection.correlator import build_incidents
from detection.engine import evaluate_job
from ioc.extractor import detect_suspicious, extract_iocs
from intelligence.aggregator import build_intel
from normalization.normalizer import normalize
from parsers.apache_parser import parse_line as apache_line
from parsers.firewall_parser import parse_kv_line
from parsers.syslog_parser import parse_line as syslog_line
from privacy.pii_detector import detect_pii

_state = {
    "task": None,
    "job_id": None,
    "running": False,
    "lines_emitted": 0,
}

ATTACKER = "185.23.45.67"
VICTIM = "10.0.0.15"
USERS = ["admin", "root", "svc_backup"]


def _now_hms() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S").replace("  ", " ")


def gen_ssh_burst() -> str:
    r = random.random()
    if r < 0.75:
        return f"{_now_hms()} srv01 sshd: Failed password for {random.choice(USERS)} from {ATTACKER}"
    if r < 0.9:
        return f"{_now_hms()} srv01 sshd: Accepted password for admin from {ATTACKER}"
    return f"{_now_hms()} srv01 sshd: Failed password for oracle from 203.0.113.{random.randint(2,254)}"


def gen_firewall() -> str:
    port = random.choice([21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 5432, 6379, 8080])
    action = "DENY" if random.random() < 0.8 else "ALLOW"
    src = ATTACKER if action == "DENY" else f"192.168.1.{random.randint(2,254)}"
    return f"SRC={src} DST={VICTIM} PROTO=TCP DPT={port} ACTION={action}"


def gen_apache() -> str:
    paths = ["/index.html", "/login", "/api/items?q=1",
             "/products.php?id=1' OR '1'='1",
             "/../../etc/passwd",
             "/search?q=<script>alert(1)</script>"]
    p = random.choice(paths)
    status = 200 if random.random() < 0.7 else random.choice([401, 403, 500])
    ip = ATTACKER if p not in paths[:3] else f"198.51.100.{random.randint(2,254)}"
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "GET {p} HTTP/1.1" {status} {random.randint(100,5000)} "-" "curl/8.0"'


GENERATORS = [(gen_ssh_burst, syslog_line, 0.4),
              (gen_firewall, parse_kv_line, 0.35),
              (gen_apache, apache_line, 0.25)]

PARSER_BY_NAME = {
    "syslog": syslog_line,
    "firewall": parse_kv_line,
    "apache": apache_line,
}


async def _stream_loop(job_id: str, interval_s: float, lines_per_tick: int):
    _state.update(running=True, lines_emitted=0)
    try:
        while _state["running"]:
            batch = []
            for _ in range(lines_per_tick):
                r = random.random()
                acc = 0.0
                chosen = GENERATORS[-1]
                for gen, parser, weight in GENERATORS:
                    acc += weight
                    if r <= acc:
                        chosen = (gen, parser, weight)
                        break
                raw = chosen[0]()
                fields = chosen[1](raw)
                ev = normalize(fields, job_id, None, raw)
                text_parts = [ev.message] + [str(v) for v in (fields or {}).values()
                                             if isinstance(v, str)]
                ev.iocs = extract_iocs(" ".join(text_parts))
                flags = detect_suspicious(ev.message)
                if flags:
                    ev.extras["suspicious"] = flags
                from core.geoip import lookup as geo_lookup
                if ev.source_ip:
                    geo = geo_lookup(ev.source_ip)
                    if geo:
                        ev.extras["geo_src"] = geo
                if ev.destination_ip:
                    geo = geo_lookup(ev.destination_ip)
                    if geo:
                        ev.extras["geo_dst"] = geo
                from core.intel import enrich_event as intel_enrich
                ref = intel_enrich(ev.source_ip, ev.destination_ip, ev.iocs)
                if ref:
                    ev.extras["intel_match"] = {
                        "value": ref["value"], "type": ref["type"],
                        "threat_type": ref["threat_type"], "severity": ref["severity"],
                        "confidence": ref["confidence"],
                        "verdict": "malicious" if ref["confidence"] >= 0.9 else "suspicious",
                    }
                    if not ev.threat_type:
                        ev.threat_type = ref["threat_type"] or "intel_match"
                    ev.risk_score = min(100, ev.risk_score + {"LOW": 0, "MEDIUM": 15,
                                                              "HIGH": 30, "CRITICAL": 45}.get(ref["severity"], 0))
                ev.pii_detected = sorted({h["type"] for h in detect_pii(ev.message)})
                batch.append((ev, raw))
            with db() as conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO raw_lines (job_id, line_no, raw) VALUES (?, ?, ?)",
                    [(job_id, _state["lines_emitted"] + i + 1, raw[:8000])
                     for i, (_, raw) in enumerate(batch)])
                conn.executemany(
                    "INSERT INTO events (event_id, job_id, line_no, ts, event_type, source,"
                    " src_ip, dst_ip, src_port, dst_port, protocol, username, hostname,"
                    " action, status, severity, message, threat_type, risk_score,"
                    " iocs_json, pii_json, mappings_json, attack_json, extras_json)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [ev.to_row() for ev, _ in batch])
            _state["lines_emitted"] += len(batch)

            if _state["lines_emitted"] % (lines_per_tick * 3) < lines_per_tick:
                await asyncio.to_thread(evaluate_job, job_id)
                from ml.model import refresh as ml_refresh
                await asyncio.to_thread(ml_refresh, job_id)
                await asyncio.to_thread(build_incidents, job_id)
                from core.assets import build_assets
                await asyncio.to_thread(build_assets, job_id)
                await asyncio.to_thread(build_intel, job_id)
                await asyncio.to_thread(evaluate_alerts, job_id)
                total = None
                with db() as conn:
                    row = conn.execute(
                        "SELECT COUNT(*) c FROM events WHERE job_id=?", (job_id,)).fetchone()
                    total = row["c"]
                jobs.merge_stats(job_id, total_lines=total)
            jobs.set_stage(job_id, "classified",
                           progress=min(99.0, _state["lines_emitted"] / 50))
            await asyncio.sleep(interval_s)
    except asyncio.CancelledError:
        pass
    finally:
        _state["running"] = False


def start_stream(interval_ms: int = 1000, lines_per_tick: int = 5) -> dict:
    if _state["running"]:
        return {"already_running": True, **{k: _state[k] for k in ("job_id", "lines_emitted")}}
    interval_s = max(0.05, min(30, interval_ms / 1000))
    lines_per_tick = max(1, min(200, lines_per_tick))
    job_id = jobs.create_job(f"live_stream_{datetime.now(timezone.utc).strftime('%H%M%S')}.log",
                             0, source_type="stream")
    jobs.update_job(job_id, status="processing", stage="normalized")
    task = asyncio.create_task(_stream_loop(job_id, interval_s, lines_per_tick))
    _state.update(task=task, job_id=job_id)
    return {"started": True, "job_id": job_id}


def stop_stream() -> dict:
    was_running = _state["running"]
    _state["running"] = False
    task = _state.get("task")
    if task and not task.done():
        task.cancel()
    if _state.get("job_id") and was_running:
        jobs.finish_job(_state["job_id"])
    return {"stopped": True, "lines_emitted": _state["lines_emitted"]}


def status() -> dict:
    return {"running": _state["running"],
            "job_id": _state.get("job_id"),
            "lines_emitted": _state["lines_emitted"]}
