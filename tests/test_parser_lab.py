"""M4: Parser Lab endpoint — live parsing, no DB writes, ingestion-parity."""

import pytest

from api.routes_parserlab import FALLBACK_LABEL, parser_lab
from core.storage import db

ASA = "%ASA-6-302013: Built inbound TCP connection 1 for outside:5.6.7.8/443 to inside:10.1.1.5/5000"
FTG = ("date=2026-08-25 time=10:30:01 devname=FW1 action=deny "
       "srcip=1.2.3.4 dstip=5.6.7.8 dstport=22 proto=6")
PAN = "<13>1 2026-08-25T10:30:01+00:00 PA-FW - - TRAFFIC,allow,1.2.3.4,5.6.7.8,1000,443,tcp"
SYSLOG = "Aug 25 10:30:01 srv01 sshd[123]: Failed password for admin from 185.23.45.67 port 5000 ssh2"
NOISE = "totally unstructured chatter with no recognizable shape 123"


def test_parser_lab_routes_named_vendors():
    body = LabBody = type("LabBody", (), {})  # placeholder, replaced below
    from api.routes_parserlab import LabBody as LB
    resp = parser_lab(LB(text="\n".join([ASA, FTG, PAN, SYSLOG])))
    parsers = {ln["parser"] for ln in resp["lines"] if ln["parser"] != "blank"}
    assert "cisco_asa" in parsers
    assert "fortinet" in parsers
    assert "palo_alto" in parsers
    assert "syslog" in parsers
    assert resp["summary"]["records"] == 4
    assert resp["summary"]["fallback_pct"] == 0.0


def test_parser_lab_fallback_label_and_counts():
    from api.routes_parserlab import LabBody as LB
    resp = parser_lab(LB(text="\n".join([NOISE, NOISE, SYSLOG])))
    s = resp["summary"]
    assert s["records"] == 3
    assert s["fallback_pct"] > 0
    noise_rows = [ln for ln in resp["lines"] if "unstructured" in ln["raw"]]
    assert all(ln["parser"] == FALLBACK_LABEL for ln in noise_rows)


def test_parser_lab_summary_tiles():
    from api.routes_parserlab import LabBody as LB
    resp = parser_lab(LB(text="\n".join([ASA, ASA, FTG, NOISE])))
    s = resp["summary"]
    assert s["records"] == 4
    assert s["named_parser_pct"] == 75.0
    assert s["fallback_pct"] == 25.0
    assert s["distinct_formats"] >= 2
    assert s["lines_per_second"] > 0
    assert resp["detected_format"] in ("cisco_asa", "fortinet", "generic")
    assert 0.0 <= resp["confidence"] <= 1.0


def test_parser_lab_writes_nothing_to_db():
    from api.routes_parserlab import LabBody as LB
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        raw_before = conn.execute("SELECT COUNT(*) c FROM raw_lines").fetchone()["c"]
    parser_lab(LB(text="\n".join([ASA, FTG, PAN, NOISE, NOISE])))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        raw_after = conn.execute("SELECT COUNT(*) c FROM raw_lines").fetchone()["c"]
    assert before == after and raw_before == raw_after


def test_parser_lab_raw_vs_normalized_fields():
    from api.routes_parserlab import LabBody as LB
    resp = parser_lab(LB(text=FTG))
    row = next(ln for ln in resp["lines"] if "devname" in ln["raw"])
    assert row["raw"] == FTG
    f = row["fields"]
    assert f["src_ip"] == "1.2.3.4" and f["dst_port"] == 22
    assert f["action"] == "deny"
