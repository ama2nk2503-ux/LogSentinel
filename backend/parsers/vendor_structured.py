"""File-level JSON handlers for vendor event streams (M4 additive).

CloudTrail, Okta, and CrowdStrike logs arrive as JSON lines or a JSON array.
These reuse the same normalization contract as parsers/structured_parser.py
(flatten objects into dot-notation field dicts) while pre-mapping the vendor
fields into the UniversalEvent vocabulary via the line parsers above.
"""

import json
from pathlib import Path

from parsers.registry import register_file
from parsers.vendor_parsers import (parse_cloudtrail_line, parse_crowdstrike_line,
                                    parse_okta_line)


def _iter_json_records(path):
    path = Path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(1)
    if head == "[":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            try:
                data = json.load(fh)
            except (ValueError, RecursionError):
                data = None
        if isinstance(data, list):
            for i, rec in enumerate(data):
                if isinstance(rec, dict):
                    yield i + 1, json.dumps(rec), rec
            return
    line_no = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line_no += 1
            s = raw.strip()
            if not s.startswith("{"):
                continue
            try:
                rec = json.loads(s)
            except (ValueError, RecursionError):
                continue
            if isinstance(rec, dict):
                yield line_no, s, rec


def _make_handler(line_parser):
    def handler(path):
        for line_no, raw, rec in _iter_json_records(path):
            fields = line_parser(raw)
            if fields is None:
                fields = {"message": raw[:1000], "event_type": "cloud_event"}
            yield line_no, raw[:2000], fields
    return handler


register_file("cloudtrail")(_make_handler(parse_cloudtrail_line))
register_file("okta")(_make_handler(parse_okta_line))
register_file("crowdstrike")(_make_handler(parse_crowdstrike_line))
