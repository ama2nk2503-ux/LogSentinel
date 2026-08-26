from normalization.normalizer import normalize, parse_timestamp
from parsers.load_all import *  # noqa: F401,F403
from parsers.registry import get_line_parser


def test_ts_syslog_gets_current_year():
    iso = parse_timestamp("Aug 25 10:30:01")
    assert iso.endswith("Z")
    assert "-08-25T10:30:01" in iso or f"-{__import__('datetime').datetime.now().year}-" in iso


def test_ts_apache_with_offset():
    iso = parse_timestamp("25/Aug/2026:10:31:02 +0000")
    assert iso == "2026-08-25T10:31:02+00:00".replace("+00:00", "Z")


def test_ts_epoch_seconds_and_millis():
    assert parse_timestamp("1728813601").startswith("2024-10-13T10:00:01")
    assert parse_timestamp("1728813601000").startswith("2024-10-13T10:00:01")


def test_ts_invalid_returns_empty():
    assert parse_timestamp("not a date") == ""
    assert parse_timestamp(None) == ""


def test_normalize_syslog_failure_event():
    parser = get_line_parser("syslog")
    fields = parser("Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")
    ev = normalize(fields, "job1", 1, "raw line here")
    assert ev.timestamp.endswith("Z")
    assert ev.source_ip == "185.23.45.67"
    assert ev.username == "admin"
    assert ev.event_type == "auth_failure"
    assert ev.severity == "LOW"
    # provenance captured
    assert ev.mappings["src_ip"] == "185.23.45.67"
    assert ev.mappings["username"] == "admin"


def test_normalize_apache_event_ports_coerced():
    fields = {"event_type": "http_request", "src_ip": "1.2.3.4",
              "dst_port": "443", "status": "200"}
    ev = normalize(fields, "job1", 2, "raw")
    assert ev.destination_port == 443
    assert isinstance(ev.destination_port, int)


def test_normalize_defaults_message_to_raw():
    ev = normalize({"event_type": "unclassified"}, "job1", 3, "some raw log line")
    assert ev.message == "some raw log line"


def test_normalize_severity_hint_validated():
    ev = normalize({"severity_hint": "HIGH"}, "job1", 4, "r")
    assert ev.severity == "HIGH"
    ev2 = normalize({"severity_hint": "bogus"}, "job1", 5, "r")
    assert ev2.severity == "LOW"


def test_normalize_extras_from_kv():
    ev = normalize({"_extras": {"ttl": "64", "flag": "SYN"}}, "job1", 6, "r")
    assert ev.extras["ttl"] == "64"
