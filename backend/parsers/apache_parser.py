"""Apache/Nginx access-log parser (common + combined formats)."""

import re

from parsers.registry import register_line

APACHE_RX = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


@register_line("apache", "nginx")
def parse_line(line: str) -> dict | None:
    m = APACHE_RX.match(line)
    if not m:
        return None
    req = (m.group("req") or "").split()
    method = path = proto = None
    if len(req) >= 1:
        method = req[0]
    if len(req) >= 2:
        path = req[1]
    if len(req) >= 3:
        proto = req[2]

    status = int(m.group("status"))
    fields = {
        "ts_raw": m.group("ts"),
        "event_type": "http_request",
        "src_ip": m.group("ip"),
        "username": None if m.group("user") == "-" else m.group("user"),
        "http_method": method,
        "http_path": path,
        "http_protocol": proto,
        "status": str(status),
        "bytes_sent": None if m.group("size") == "-" else int(m.group("size")),
        "referrer": m.group("ref"),
        "user_agent": m.group("ua"),
        "message": m.group("req"),
        "action": {2: "allow", 3: "allow", 4: "client_error", 5: "server_error"}.get(status // 100, "unknown"),
    }
    return fields
