import json

import pytest

from core import intel
from core.storage import db


@pytest.fixture(scope="module", autouse=True)
def seeded_feed():
    assert intel.seed_intel_reference() >= 3, "reference feed must seed"
    return True


def test_reference_feed_seeded_and_listable():
    refs = {r["value"]: r for r in intel.list_reference()}
    assert "185.23.45.67" in refs, "bundled attacker IP must be in the feed"
    assert refs["185.23.45.67"]["confidence"] >= 0.9
    assert refs["185.23.45.67"]["threat_type"]


def test_reload_resets_to_feed():
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO intel_reference"
                     " (value, type, threat_type, severity, confidence, source)"
                     " VALUES (?,?,?,?,?,?)",
                     ("stale.example.invalid", "domain", "C2", "HIGH", 0.9, "test"))
    count = intel.reload_intel_reference()
    refs = {r["value"] for r in intel.list_reference()}
    assert count >= 3
    assert "stale.example.invalid" not in refs


def test_reputation_verdicts():
    bad = intel.reputation("185.23.45.67")
    assert bad["verdict"] in ("malicious", "suspicious")
    assert bad["threat_type"] and bad["confidence"] >= 0.7
    good = intel.reputation("192.168.1.10")
    assert good["verdict"] == "unknown"
    assert good["sightings"] == []


def test_reputation_includes_sightings():
    with db() as conn:
        conn.execute(
            "INSERT INTO indicators (value, type, threat_type, severity, confidence,"
            " first_seen, last_seen, related_events)"
            " VALUES (?,?,?,?,?,?,?,?)",
            ("m2.badhost.example", "domain", "C2", "HIGH", 0.95,
             "2026-08-25T00:00:00Z", "2026-08-25T00:01:00Z", 5))
    rep = intel.reputation("m2.badhost.example")
    assert rep["verdict"] == "malicious"
    assert rep["related_events"] == 5
    assert len(rep["sightings"]) == 1


def test_enrich_event_prefers_src_then_ioc():
    ref = intel.enrich_event("185.23.45.67", "10.0.0.15", [])
    assert ref is not None and ref["value"] == "185.23.45.67"
    ref2 = intel.enrich_event("8.8.8.8", "203.0.113.9", [])
    assert ref2 is not None and ref2["value"] == "203.0.113.9"
    assert intel.enrich_event("8.8.8.8", "10.0.0.15", []) is None
    ioc_hit = intel.enrich_event("9.9.9.9", "10.0.0.15", [{"value": "185.23.45.67", "type": "ipv4"}])
    assert ioc_hit is not None and ioc_hit["value"] == "185.23.45.67"


def test_pipeline_embeds_intel_match_and_geo():
    from core import jobs, pipeline
    from core.config import settings

    job_id = jobs.create_job("m2_enrich.log", 0)
    body = "\n".join(
        f"Aug 25 09:0{i}:01 srv01 sshd: Failed password for admin from 185.23.45.67"
        for i in range(3)) + "\n"
    path = settings.upload_dir / f"{job_id}__m2_enrich.log"
    path.write_text(body, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()
    with db() as conn:
        row2 = conn.execute("SELECT status, stage FROM jobs WHERE id = ?", (job_id,)).fetchone()
        rows = conn.execute(
            "SELECT src_ip, extras_json, risk_score FROM events WHERE job_id = ?",
            (job_id,)).fetchall()
    assert row2 and row2["status"] == "done"
    assert rows
    got_match = got_geo = risk_bumped = False
    for r in rows:
        extras = json.loads(r["extras_json"] or "{}")
        if extras.get("intel_match") and extras["intel_match"]["value"] == "185.23.45.67":
            got_match = True
        if extras.get("geo_src") and extras["geo_src"]["kind"] == "public":
            got_geo = True
        if int(r["risk_score"]) >= 30:
            risk_bumped = True
    assert got_match, "reference intel match must be embedded for known-bad source"
    assert got_geo, "geo enrichment must be embedded for public source"
    assert risk_bumped, "known-bad reference must bump risk score"