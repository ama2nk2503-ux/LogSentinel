"""VMware vCenter parser: vpxd/vsphere-ui authentication and audit markers."""

import re

from parsers.registry import register_line

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
TS_RX = re.compile(r"^\s*(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
MARKER = re.compile(r"\bvpxd?\[\d+\]|\[VpxLRO|\[Originator@\d+\]|\bvsphere-ui\b")
AUTH_OK_RX = re.compile(
    r"\buser '(?P<user>[^']+)' authenticated from (?P<src>{ip})\b".format(ip=IP), re.I)
AUTH_FAIL_RX = re.compile(
    r"\buser '(?P<user>[^']+)' failed to authenticate from (?P<src>{ip})\b".format(ip=IP), re.I)
LOCKOUT_RX = re.compile(r"\buser '(?P<user>[^']+)' lockout\b", re.I)


@register_line("vcenter")
def parse_vcenter_line(line: str) -> dict | None:
    m = TS_RX.match(line)
    if not m:
        return None
    ts_raw = m.group("ts")
    body = line[m.end():]
    if not MARKER.search(body):
        return None

    for rx, ev_type, severity in ((AUTH_FAIL_RX, "auth_failure", "HIGH"),
                                   (LOCKOUT_RX, "auth_failure", "HIGH"),
                                   (AUTH_OK_RX, "auth_success", None)):
        mm = rx.search(body)
        if mm:
            fields = {
                "event_type": ev_type,
                "source": "vmware-vcenter",
                "username": mm.group("user"),
                "ts_raw": ts_raw,
                "message": line,
                "severity_hint": severity,
            }
            if mm.groupdict().get("src"):
                fields["src_ip"] = mm.group("src")
            if rx is LOCKOUT_RX:
                fields["action"] = "lock"
            return fields
    return None