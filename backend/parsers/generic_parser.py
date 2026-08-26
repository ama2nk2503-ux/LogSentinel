"""Generic fallback parser: best-effort timestamp/IP/KV extraction from any line."""

import re

from parsers.registry import register_line

ISO_TS = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)"
)
SYSLOG_TS = re.compile(r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
IPV4 = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
KV_PAIR = re.compile(r"\b([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|[^\s]+)")
DENY_WORDS = ("deny", "denied", "block", "blocked", "drop", "dropped", "reject", "failed")


@register_line("generic")
def parse_generic_line(line: str) -> dict | None:
    fields: dict = {"event_type": "unclassified", "message": line}
    im = ISO_TS.search(line) or SYSLOG_TS.search(line)
    if im:
        fields["ts_raw"] = im.group("ts")
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    if ips:
        fields["src_ip"] = ips[0]
        if len(ips) > 1:
            fields["dst_ip"] = ips[1]
    pairs = KV_PAIR.findall(line)
    if len(pairs) >= 2:
        extras = {k.lower(): v.strip('"') for k, v in pairs}
        fields["_extras"] = extras
    low = line.lower()
    if any(w in low for w in DENY_WORDS):
        fields["action"] = "deny"
        fields["status"] = "failure"
    return fields
