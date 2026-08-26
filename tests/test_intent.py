import pytest

from detection.intent import parse_intent


def test_master_prompt_query_parses():
    r = parse_intent("show me all high-risk authentication attacks from the last hour")
    chips = {(c["key"], c["value"]) for c in r["chips"]}
    f = r["filters"]
    assert ("severity", "HIGH") in chips
    assert ("window", "last 60m") in chips
    assert ("type~", "authentication*") in chips
    assert f["severity"] == "HIGH" and f["since_minutes"] == 60 and f["auth_events"]


def test_threat_synonyms():
    assert parse_intent("port scan activity")["filters"]["threat_like"] == "Port Scanning"
    assert parse_intent("SQL injection attempts")["filters"]["threat_like"] == "Web Attack"
    assert parse_intent("bruteforce")["filters"]["threat_like"] == "Brute Force"


def test_ip_entity_extracted():
    r = parse_intent("why is 185.23.45.67 dangerous")
    assert r["filters"]["q"] == "185.23.45.67"


def test_pii_and_ioc_intents():
    f = parse_intent("events with email detected")["filters"]
    assert f.get("has_pii") is True
    f2 = parse_intent("list extracted domains")["filters"]
    assert f2.get("ioc_type") == "domain"


def test_no_intent_falls_back():
    r = parse_intent("zebra unicorn sparkle")
    assert r["filters"].get("fallback_text") is True
    assert len(r["chips"]) == 0


def test_time_variants():
    assert parse_intent("last 24 hours")["filters"]["since_minutes"] == 1440
    assert parse_intent("last 15 minutes")["filters"]["since_minutes"] == 15
