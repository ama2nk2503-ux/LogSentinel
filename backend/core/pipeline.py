"""Pipeline orchestrator.

Flow: sample -> detect format (confidence) -> parse via registry ->
normalize -> UniversalEvent -> batched SQLite persistence.
IOC / rules / correlation hook in at marked extension points (P4+).
"""

import time
from collections import Counter

from core import jobs
from core.config import settings
from core.ingest import iter_line_chunks
from core.storage import db
from mining.template_miner import (MIN_CONFIDENCE, load_templates,
                                   mine_templates, parse_learned_line,
                                   persist_templates)
from ioc.extractor import detect_suspicious, extract_iocs
from normalization.normalizer import normalize
from parsers.detector import detect_format
from parsers.load_all import *  # noqa: F401,F403 — registers all parsers
from parsers.registry import get_file_handler, get_line_parser
from privacy.pii_detector import detect_pii

FLUSH = 2000

_SEVERITY_BUMP = {"LOW": 0, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 45}


def _severity_bump(severity: str) -> int:
    return _SEVERITY_BUMP.get((severity or "").upper(), 0)


def _detect(job_id: str, path) -> dict:
    sample_batch = next(iter_line_chunks(path, chunk_lines=400), [])
    info = detect_format(sample_batch)
    label = info.get("subtype") or info["format"]
    jobs.update_job(job_id, detected_format=label,
                    format_confidence=round(info["confidence"] * 100))
    jobs.merge_stats(job_id, format_scores=info["scores"])
    return info


def run_job(job_id: str) -> None:
    try:
        jobs.update_job(job_id, status="processing")
        path = next(settings.upload_dir.glob(f"{job_id}__*"), None)
        if path is None:
            jobs.fail_job(job_id, "Uploaded file missing on disk")
            return

        t0 = time.perf_counter()
        fmt_info = _detect(job_id, path)
        jobs.set_stage(job_id, "detected")

        fmt = fmt_info["format"]
        handler = get_file_handler(fmt)
        parser = get_line_parser(fmt)

        # --- M4: unsupervised template mining fallback ---------------------
        # When format detection confidence is below threshold, learn line
        # templates offline (Drain-style) BEFORE falling back to generic.
        learned_templates: list[dict] = []
        use_miner = (handler is None and parser is None) or (
            handler is None and fmt_info["confidence"] < MIN_CONFIDENCE)
        if use_miner:
            sample_lines = next(iter_line_chunks(path, chunk_lines=2000), [])
            learned_templates = mine_templates(sample_lines)
            persist_templates(job_id, learned_templates)
            jobs.merge_stats(job_id, learned_templates=len(learned_templates),
                             parsed_by="learned_template")

        total = normalized = 0
        pii_events = 0
        type_counts: Counter[str] = Counter()
        ioc_type_counts: Counter[str] = Counter()
        ioc_total = 0
        raw_buf: list[tuple] = []
        event_buf: list[tuple] = []

        def handle(line_no, raw, fields):
            nonlocal total, normalized, ioc_total, pii_events
            total += 1
            raw_buf.append((job_id, line_no or total, raw[:8000]))
            ev = normalize(fields, job_id, line_no or total, raw)
            # --- S08: IOC extraction over message + high-signal fields ---
            fields = fields or {}
            ioc_text = " ".join(str(x) for x in (
                ev.message,
                fields.get("http_path") or "",
                fields.get("url") or "",
                fields.get("command_line") or "",
                fields.get("domain") or "",
            ) if x)
            ev.iocs = extract_iocs(ioc_text)
            flags = detect_suspicious(ioc_text)
            if flags:
                ev.extras["suspicious"] = flags
            if ev.iocs:
                ioc_total += len(ev.iocs)
                for i in ev.iocs:
                    ioc_type_counts[i["type"]] += 1
            # --- M2: offline GeoIP enrichment for src/dst addresses ---
            from core.geoip import lookup as geo_lookup
            if ev.source_ip:
                geo = geo_lookup(ev.source_ip)
                if geo:
                    ev.extras["geo_src"] = geo
            if ev.destination_ip:
                geo = geo_lookup(ev.destination_ip)
                if geo:
                    ev.extras["geo_dst"] = geo
            # --- M2: reference threat-intel enrichment (risk bump when hit) ---
            from core.intel import enrich_event as intel_enrich
            ref = intel_enrich(ev.source_ip, ev.destination_ip, ev.iocs)
            if ref:
                ev.extras["intel_match"] = {
                    "value": ref["value"], "type": ref["type"],
                    "threat_type": ref["threat_type"], "severity": ref["severity"],
                    "confidence": ref["confidence"], "verdict": "malicious" if ref["confidence"] >= 0.9 else "suspicious",
                }
                if not ev.threat_type:
                    ev.threat_type = ref["threat_type"] or "intel_match"
                ev.risk_score = min(100, ev.risk_score + _severity_bump(ref["severity"]))
            # --- S09: PII detection recorded on the event ---
            ev.pii_detected = sorted({h["type"] for h in detect_pii(ev.message)})
            if ev.pii_detected:
                nonlocal pii_events
                pii_events += 1
            if fields:
                normalized += 1
                type_counts[ev.event_type] += 1
            event_buf.append(ev.to_row())
            if len(raw_buf) >= FLUSH:
                flush()

        def flush():
            if raw_buf:
                with db() as conn:
                    conn.executemany(
                        "INSERT OR REPLACE INTO raw_lines (job_id, line_no, raw) VALUES (?, ?, ?)",
                        raw_buf,
                    )
                    conn.executemany(
                        "INSERT INTO events (event_id, job_id, line_no, ts, event_type, source,"
                        " src_ip, dst_ip, src_port, dst_port, protocol, username, hostname,"
                        " action, status, severity, message, threat_type, risk_score,"
                        " dedup_event_id, timestamp_source,"
                        " iocs_json, pii_json, mappings_json, attack_json, extras_json)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        event_buf,
                    )
                    # M4 chain-of-custody: extend the per-job hash chain after
                    # each batch insert (never breaks ingestion).
                    from core.hashchain import append_batch
                    append_batch(conn, job_id)
                raw_buf.clear()
                event_buf.clear()

        if handler is not None:
            for line_no, raw, fields in handler(path):
                handle(line_no, raw, fields)
        else:
            line_no = 0
            for batch in iter_line_chunks(path):
                for raw in batch:
                    line_no += 1
                    if use_miner:
                        fields = parse_learned_line(
                            raw, learned_templates,
                            generic_parser=get_line_parser("generic"))
                    else:
                        fields = parser(raw) if parser else None
                    handle(line_no, raw, fields)
                jobs.set_stage(job_id, "normalized", progress=min(99.0, total / 1000))
        flush()

        elapsed = time.perf_counter() - t0
        jobs.merge_stats(
            job_id,
            total_lines=total,
            parsed_lines=normalized,
            unparsed_lines=total - normalized,
            event_types=dict(type_counts.most_common(20)),
            total_iocs=ioc_total,
            ioc_types=dict(ioc_type_counts.most_common()),
            pii_events=pii_events,
            parser="file:" + fmt if handler else fmt,
            process_seconds=round(elapsed, 3),
            lines_per_second=int(total / elapsed) if elapsed > 0 else 0,
        )
        # P5/P6 extension points: rules / correlation over persisted events.
        jobs.set_stage(job_id, "ioc_extracted")
        from detection.correlator import build_incidents
        from detection.engine import evaluate_job
        dets = evaluate_job(job_id)
        # In-loop ML: fit a seeded IsolationForest on the job's events and tag
        # anomalies. build_incidents() consumes these scores to escalate
        # detections whose evidence is anomalous (evidence-backed, explainable).
        from ml.model import train_job as ml_train
        ml_stats = ml_train(job_id)
        incidents = build_incidents(job_id)
        stats_update = {}
        if dets:
            stats_update["detections"] = len(dets)
        if incidents:
            stats_update["incidents"] = len(incidents)
        if ml_stats.get("trained"):
            stats_update["ml_trained"] = 1
            stats_update["ml_anomalies"] = ml_stats["n_anomalies"]
        if stats_update:
            jobs.merge_stats(job_id, **stats_update)
        # Asset inventory derived from events + detection/incident context;
        # built before alerting so per-asset alert rules can gate on it.
        from core.assets import build_assets
        build_assets(job_id)
        # Alerting runs isolated: a rule problem must never fail ingestion.
        alert_stats = {}
        try:
            from core.alerts import evaluate_alerts
            created_alerts = evaluate_alerts(job_id)
            if created_alerts:
                alert_stats["alerts"] = len(created_alerts)
        except Exception as exc:  # noqa: BLE001 — alerting must not fail the job
            alert_stats["alerts_error"] = f"{type(exc).__name__}: {exc}"
        if alert_stats:
            jobs.merge_stats(job_id, **alert_stats)
        from intelligence.aggregator import build_intel
        intel = build_intel(job_id)
        jobs.merge_stats(job_id, intel_indicators=len(intel["indicators"]),
                         intel_reports=len(intel["reports"]))
        from detection.attack import enrich_job
        enrich_job(job_id)
        jobs.update_job(job_id, stage="classified", status="done", progress=100.0)
    except Exception as exc:  # noqa: BLE001 — job isolation; error surfaces in job row
        jobs.fail_job(job_id, f"{type(exc).__name__}: {exc}")
