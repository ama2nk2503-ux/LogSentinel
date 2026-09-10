"""Pre-download validation of generated SIEM output. Never serve unvalidated."""

import json
import re


class ExportValidationError(Exception):
    pass


def validate_json(text: str) -> None:
    try:
        obj = json.loads(text)
    except ValueError as e:
        raise ExportValidationError(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict) or "events" not in obj:
        raise ExportValidationError("JSON export missing events array")


def validate_csv(text: str) -> None:
    lines = [l for l in text.splitlines() if l]
    if len(lines) < 1:
        raise ExportValidationError("empty CSV")
    cols = text.splitlines()[0].count(",") + 1
    for i, line in enumerate(lines[1:], start=2):
        # account for quoted commas: rough structural check only
        if line.count('"') % 2 != 0:
            raise ExportValidationError(f"unbalanced quotes on row {i}")


CEF_HEADER = re.compile(r"^CEF:\d\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|")


def validate_cef(text: str) -> None:
    if not text.strip():
        raise ExportValidationError("empty CEF")
    for i, line in enumerate(text.splitlines(), start=1):
        if not CEF_HEADER.match(line):
            raise ExportValidationError(f"line {i}: malformed CEF header")
        header_pipes = line.count("|")
        if header_pipes < 6:
            raise ExportValidationError(f"line {i}: too few CEF header fields")


def validate_leef(text: str) -> None:
    if not text.strip():
        raise ExportValidationError("empty LEEF")
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("LEEF:1.0|") or "|" not in line:
            raise ExportValidationError(f"line {i}: malformed LEEF header")


STIX_ID = re.compile(r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def validate_stix(text: str) -> None:
    try:
        bundle = json.loads(text)
    except ValueError as e:
        raise ExportValidationError(f"invalid STIX JSON: {e}") from e
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ExportValidationError("not a STIX bundle")
    for obj in bundle["objects"]:
        if obj.get("type") != "indicator":
            continue
        if not STIX_ID.match(obj.get("id", "")):
            raise ExportValidationError(f"bad indicator id: {obj.get('id')}")
        pattern = obj.get("pattern", "")
        if not (pattern.startswith("[") and pattern.endswith("]") and "=" in pattern):
            raise ExportValidationError(f"bad indicator pattern: {pattern}")


def validate_syslog(text: str) -> None:
    if not text.strip():
        raise ExportValidationError("empty syslog")
    for i, line in enumerate(text.splitlines(), start=1):
        if not re.match(r"^<\d{1,3}>", line):
            raise ExportValidationError(f"line {i}: missing PRI")


VALIDATORS = {
    "json": validate_json,
    "csv": validate_csv,
    "cef": validate_cef,
    "leef": validate_leef,
    "stix": validate_stix,
    "syslog": validate_syslog,
    "ecs": validate_json,
    "ocsf": validate_json,
}


def validate_export(fmt: str, payload: str) -> None:
    validator = VALIDATORS.get(fmt)
    if validator is None:
        raise ExportValidationError(f"unknown format '{fmt}'")
    validator(payload)
