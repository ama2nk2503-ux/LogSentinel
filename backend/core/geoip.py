"""Offline, deterministic GeoIP geolocation.

A bundled range table (rules/geoip/ranges.csv) is loaded once into a sorted
list and queried with binary search. Never talks to the network — every
src/dst IP resolves to a stable, reproducible location (or None when the
range is not covered). Private/reserved networks are labelled so analysts
can distinguish internal hosts from internet-facing endpoints.
"""

import bisect
import csv
from pathlib import Path

RANGES_CSV = Path(__file__).resolve().parent.parent.parent / "rules" / "geoip" / "ranges.csv"

_loaded: list[tuple[int, int, dict]] | None = None


def _load() -> list[tuple[int, int, dict]]:
    rows = []
    if RANGES_CSV.exists():
        with open(RANGES_CSV, "r", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                try:
                    start = int(r["network_start"])
                    end = int(r["network_end"])
                except (KeyError, ValueError):
                    continue
                rows.append((start, end, {
                    "country_code": r.get("country_code", ""),
                    "country": r.get("country", ""),
                    "city": r.get("city", ""),
                    "asn": r.get("asn", ""),
                    "org": r.get("org", ""),
                    "latitude": float(r.get("latitude", 0)),
                    "longitude": float(r.get("longitude", 0)),
                    "kind": r.get("kind", "public") or "public",
                }))
    rows.sort(key=lambda r: r[0])
    return rows


def _db():
    global _loaded
    if _loaded is None:
        _loaded = _load()
    return _loaded


def _to_int(ip: str) -> int | None:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


def lookup(ip: str) -> dict | None:
    """Resolve an IPv4 address to its geo record, or None when unknown."""
    ip_int = _to_int(ip or "")
    if ip_int is None:
        return None
    rows = _db()
    i = bisect.bisect_right(rows, (ip_int, (1 << 32) - 1, {})) - 1
    if i < 0:
        return None
    start, end, rec = rows[i]
    if start <= ip_int <= end:
        return {**rec, "network_start": start, "network_end": end, "ip": ip}
    return None


def is_public(geo: dict | None) -> bool:
    return bool(geo and geo.get("kind") == "public")