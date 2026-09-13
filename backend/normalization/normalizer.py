"""Normalizer: parser field dicts -> UniversalEvent rows with provenance."""

import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from normalization.identity import deterministic_event_id
from normalization.schema import UniversalEvent

TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%d/%b/%Y %H:%M:%S",
]

ALIASES = {
    "src_ip": "source_ip", "source_ip": "source_ip", "ip": "source_ip",
    "dst_ip": "destination_ip", "destination_ip": "destination_ip",
    "dst_port": "destination_port", "dest_port": "destination_port",
    "src_port": "source_port",
}

VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@lru_cache(maxsize=200_000)
def _parse_timestamp_cached(raw: str) -> str:
    # epoch seconds / millis
    if raw.replace(".", "", 1).isdigit():
        try:
            val = float(raw)
            if val > 1e12:
                val /= 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            pass
    now_year = datetime.now().year
    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(f"{raw} {now_year}", fmt + " %Y") \
                if fmt == "%b %d %H:%M:%S" else datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            if fmt == "%b %d %H:%M:%S":
                now = datetime.now()
                dt = dt.replace(year=now.year)
                if dt > now + timedelta(days=1):
                    dt = dt.replace(year=now.year - 1)
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return ""


def parse_timestamp(raw: str | None) -> str:
    if not raw:
        return ""
    return _parse_timestamp_cached(str(raw).strip())


def normalize(fields: dict | None, job_id: str, line_no: int | None,
              raw: str) -> UniversalEvent:
    fields = fields or {}
    ev = UniversalEvent(job_id=job_id, line_no=line_no)
    ev.event_id = uuid.uuid4().hex
    mappings: dict = {}

    ts_raw = None
    ts_source = "ingest"
    for key, value in fields.items():
        if key.startswith("_"):
            continue
        canon = ALIASES.get(key, key)
        mappings[key] = value if isinstance(value, (str, int, float)) else str(value)
        if canon == "ts_raw" or (key in ("timestamp", "time", "@timestamp", "ts") and not ev.timestamp):
            ts_raw = ts_raw or value
            continue
        if canon in ("timestamp", "time", "@timestamp", "ts") and not ev.timestamp:
            ts_raw = ts_raw or value
            continue
        if hasattr(ev, canon):
            cur = getattr(ev, canon)
            if cur in ("", None, []) or (canon == "event_type" and cur == "unclassified"):
                setattr(ev, canon, _coerce(canon, value))

    if ts_raw is not None and isinstance(ts_raw, dict):
        ts_raw = json_or_str(ts_raw)
    parsed_ts = parse_timestamp(ts_raw if isinstance(ts_raw, str) else None)
    if parsed_ts:
        ev.timestamp = parsed_ts
        ts_source = "event"
    ev.timestamp_source = ts_source

    sev = str(fields.get("severity_hint", "") or "").upper()
    ev.severity = sev if sev in VALID_SEVERITY else "LOW"
    if not ev.message:
        ev.message = (raw or "")[:500]
    if not ev.source:
        ev.source = fields.get("source", "")
    ev.extras = dict(fields.get("_extras") or {})
    ev.mappings = mappings
    # Deterministic identity: hash of (timestamp|hostname|process|raw_text).
    # The full raw line keeps ids stable regardless of parser coverage; the
    # constant marker stands in when no timestamp could be parsed.
    ev.dedup_event_id = deterministic_event_id(
        ev.timestamp, ev.hostname, ev.source, raw or ev.message)
    return ev


def _coerce(canon: str, value):
    if canon.endswith("_port"):
        try:
            return int(str(value))
        except ValueError:
            return None
    if isinstance(value, (dict, list)):
        return json_or_str(value)
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def json_or_str(v) -> str:
    import json
    try:
        return json.dumps(v)
    except (TypeError, ValueError):
        return str(v)
