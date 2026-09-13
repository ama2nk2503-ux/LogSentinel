"""M4: unsupervised template mining fallback tests.

The miner runs when format-detection confidence is below threshold, before
the generic fallback. Learned templates persist per job; provenance is
tagged parsed_by=learned_template alongside named_parser/generic_fallback.
"""

from core.storage import db
from mining.template_miner import (MIN_CONFIDENCE, extract_timestamp_from_template,
                                   load_templates, mine_templates,
                                   parse_learned_line, persist_templates)
from parsers.detector import detect_format
from parsers.load_all import *  # noqa: F401,F403


NOISY_LINES = [
    "process 4821 started module alpha at 2026-08-25 10:30:01",
    "process 8823 started module beta at 2026-08-25 10:30:02",
    "process 1203 started module alpha at 2026-08-25 10:30:03",
    "connection 5521 opened to 10.0.0.15 port 443",
    "connection 9902 opened to 10.0.0.15 port 22",
    "cache flush completed in 210 ms",
    "cache flush completed in 305 ms",
    "cache flush completed in 188 ms",
]


def test_unknown_format_has_low_confidence():
    info = detect_format(NOISY_LINES)
    assert info["format"] == "generic"
    assert info["confidence"] < MIN_CONFIDENCE


def test_mine_templates_groups_and_counts():
    templates = mine_templates(NOISY_LINES)
    by_mask = {t["template"]: t for t in templates}
    # variable parts masked, constants kept
    proc = next(t for t in templates if t["template"].startswith("process"))
    assert "<DIGIT>" in proc["template"] and "started module" in proc["template"]
    flush_t = next(t for t in templates if t["template"].startswith("cache"))
    assert flush_t["count"] == 3 and "<DURATION>" in flush_t["template"]
    conn_t = next(t for t in templates if t["template"].startswith("connection"))
    assert "<IPV4>" in conn_t["template"]
    # deterministic across runs
    assert mine_templates(NOISY_LINES) == templates


def test_min_support_filters_singletons():
    templates = mine_templates(NOISY_LINES, min_support=3)
    assert all(t["count"] >= 3 for t in templates)


def test_extract_timestamp_from_template_line():
    ts = extract_timestamp_from_template("process 4821 started at 2026-08-25 10:30:01 now")
    assert ts.endswith("Z") and "2026-08-25T10:30:01" in ts
    assert extract_timestamp_from_template("no time in this line") == ""


def test_parse_learned_line_tags_provenance():
    templates = mine_templates(NOISY_LINES)
    f = parse_learned_line("process 7777 started module gamma at 2026-08-25 11:00:00", templates)
    assert f is not None
    assert f["_extras"]["parsed_by"] == "learned_template"
    assert f["ts_raw"] == "2026-08-25 11:00:00"
    # a line matching no learned template defers to the generic parser
    f2 = parse_learned_line("SRC=1.2.3.4 DST=5.6.7.8 ACTION=DENY", templates,
                            generic_parser=lambda l: {"event_type": "firewall_event"})
    assert f2["event_type"] == "firewall_event"


def test_persist_and_load_templates_per_job():
    job = "t_mine"
    persist_templates(job, mine_templates(NOISY_LINES))
    rows = load_templates(job)
    assert len(rows) == len(mine_templates(NOISY_LINES))
    assert rows[0]["line_count"] >= rows[-1]["line_count"]
    # re-persist replaces (no duplicates)
    persist_templates(job, mine_templates(NOISY_LINES))
    assert len(load_templates(job)) == len(rows)


def test_pipeline_end_to_end_mines_unknown_format():
    from core import jobs, pipeline
    from core.config import settings

    job_id = jobs.create_job("mystery.log", 0)
    body = "\n".join(NOISY_LINES) + "\n"
    path = settings.upload_dir / f"{job_id}__mystery.log"
    path.write_text(body, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()

    with db() as conn:
        job = conn.execute("SELECT status, stats_json FROM jobs WHERE id = ?",
                           (job_id,)).fetchone()
        rows = conn.execute(
            "SELECT event_type, extras_json, COUNT(*) c FROM events WHERE job_id = ?"
            " GROUP BY event_type, extras_json", (job_id,)).fetchall()
        tpl = conn.execute(
            "SELECT COUNT(*) c FROM learned_templates WHERE job_id = ?",
            (job_id,)).fetchone()["c"]
    assert job["status"] == "done"
    assert tpl >= 3, "templates must persist per job"
    import json
    stats = json.loads(job["stats_json"])
    assert stats.get("parsed_by") == "learned_template"
    learned = [r for r in rows if r["event_type"] == "learned_template_event"]
    assert learned, "template-matched lines must be tagged learned_template_event"
    tagged = sum(r["c"] for r in learned)
    assert tagged >= 6, "most lines should match a learned template"
    extras = json.loads(learned[0]["extras_json"])
    assert extras.get("parsed_by") == "learned_template"
