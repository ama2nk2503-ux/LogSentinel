"""VMware ESXi parser: hostd/vmkernel account-lockout and login lines (M5)."""

import re

from parsers.registry import register_line

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
TS_RX = re.compile(r"^\s*(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
MARKER = re.compile(r"\b(?:hostd|vpxa|vmkernel[\w-]*|vobd|dcui|vc-endpoint)\[\d+\]|\[originator@\d+\]")
FAIL_RX = re.compile(
    r"\bfailed login for user '(?P<user>[^']+)' from (?P<src>{ip})".format(ip=IP), re.I)
AUTH_FAIL_RX = re.compile(
    r"\blogin authentication failed for user '(?P<user>[^']+)' from (?P<src>{ip})".format(ip=IP), re.I)
LOCK_RX = re.compile(
    r"\buser '(?P<user>[^']+)' was locked(?: out)? after \d+ failed login attempts", re.I)
AUTH_OK_RX = re.compile(
    r"\bauthenticated user '(?P<user>[^']+)' from (?P<src>{ip})".format(ip=IP), re.I)

LOCKUP_EVENT = "UserAccountLockedEvent"


@register_line("esxi")
def parse_esxi_line(line: str) -> dict | None:
    m = TS_RX.match(line)
    if not m:
        return None
    ts_raw = m.group("ts")
    body = line[m.end():]
    if not MARKER.search(body) and LOCKUP_EVENT not in body:
        return None

    for rx, ev_type, severity in ((FAIL_RX, "auth_failure", "HIGH"),
                                   (AUTH_FAIL_RX, "auth_failure", "HIGH"),
                                   (LOCK_RX, "auth_failure", "HIGH"),
                                   (AUTH_OK_RX, "auth_success", None)):
        mm = rx.search(body)
        if mm:
            fields = {
                "event_type": ev_type,
                "source": "vmware-esxi",
                "username": mm.group("user"),
                "ts_raw": ts_raw,
                "message": line,
                "severity_hint": severity,
            }
            if mm.groupdict().get("src"):
                fields["src_ip"] = mm.group("src")
            if ev_type == "auth_failure" and rx is LOCK_RX:
                fields["action"] = "lock"
            return fields
    return None