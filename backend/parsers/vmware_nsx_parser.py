"""VMware NSX-T parser: management-plane audit and edge firewall drop lines."""

import re

from parsers.registry import register_line

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
TS_RX = re.compile(r"^\s*(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
MARKER = re.compile(r"\bnsxmanager(?:-\S+)?\s+\d+\s+audit:|\[Firewall\]|\[ManagementPlane\]")
AUDIT_OK_RX = re.compile(
    r"\baudit:\s*user '(?P<user>[^']+)'(?:\[[^\]]*\])?.*?\b(?:authenticated successfully|logged in)\b.*?\bfrom (?P<src>{ip})".format(ip=IP), re.I)
AUDIT_FAIL_RX = re.compile(
    r"\baudit:\s*user '(?P<user>[^']+)'(?:\[[^\]]*\])?.*?\bfailed to authenticate\b.*?\bfrom (?P<src>{ip})".format(ip=IP), re.I)
DROP_RX = re.compile(
    r"\[Firewall\].*?\b(?P<action>block|drop|deny)\s+(?P<proto>[A-Za-z]+)\s+from\s+(?P<src>{ip}):(?P<sport>\d+)\s+to\s+(?P<dst>{ip}):(?P<dport>\d+)".format(ip=IP), re.I)


@register_line("nsx")
def parse_nsx_line(line: str) -> dict | None:
    m = TS_RX.match(line)
    if not m:
        return None
    ts_raw = m.group("ts")
    body = line[m.end():]
    if not MARKER.search(body):
        return None

    d = DROP_RX.search(body)
    if d:
        return {
            "event_type": "firewall_event",
            "source": "vmware-nsx",
            "status": "deny",
            "action": d.group("action"),
            "protocol": d.group("proto").lower(),
            "src_ip": d.group("src"),
            "src_port": int(d.group("sport")),
            "dst_ip": d.group("dst"),
            "dst_port": int(d.group("dport")),
            "ts_raw": ts_raw,
            "message": line,
            "severity_hint": "MEDIUM",
        }

    for rx, ev_type, severity in ((AUDIT_OK_RX, "auth_success", None),
                                   (AUDIT_FAIL_RX, "auth_failure", "HIGH")):
        mm = rx.search(body)
        if mm:
            fields = {
                "event_type": ev_type,
                "source": "vmware-nsx",
                "username": mm.group("user"),
                "src_ip": mm.group("src"),
                "ts_raw": ts_raw,
                "message": line,
                "severity_hint": severity,
            }
            if ev_type == "auth_success":
                fields["status"] = "success"
            else:
                fields["status"] = "failure"
            return fields
    return None