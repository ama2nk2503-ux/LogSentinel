import csv

from core import geoip
from core.geoip import RANGES_CSV, is_public, lookup


def _load_rows():
    with open(RANGES_CSV, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_range_table_is_sorted_no_overlap():
    rows = sorted(_load_rows(), key=lambda r: int(r["network_start"]))
    assert len(rows) >= 5
    assert all(int(r["network_end"]) >= int(r["network_start"]) for r in rows)
    for prev, cur in zip(rows, rows[1:]):
        assert int(cur["network_start"]) > int(prev["network_end"]), "ranges must not overlap"


def test_private_and_reserved_networks_resolve():
    for ip, kind in (("10.0.0.15", "private"), ("192.168.1.7", "private"),
                     ("172.16.0.1", "private"), ("127.0.0.1", "private"),
                     ("169.254.0.1", "private"), ("0.0.0.0", "reserved"),
                     ("198.51.100.7", "reserved"), ("203.0.113.9", "reserved")):
        rec = lookup(ip)
        assert rec is not None, f"{ip} should resolve"
        assert rec["kind"] == kind, f"{ip} expected kind {kind}"


def test_sample_public_ranges_resolve():
    for ip in ("185.23.45.67", "8.8.8.8"):
        rec = lookup(ip)
        assert rec is not None, f"{ip} should resolve"
        assert rec["kind"] == "public"
        assert is_public(rec)


def test_unknown_or_malformed_ip_returns_none():
    assert lookup("999.1.1.1") is None
    assert lookup("not-an-ip") is None
    assert lookup("") is None
    assert lookup(None) is None
    assert lookup("1.2.3.4.5") is None
    assert lookup("fe80::1") is None


def test_lookup_is_deterministic_on_attacker():
    first = lookup("185.23.45.67")
    second = lookup("185.23.45.67")
    assert first == second
    assert first["country_code"] and first["country"]