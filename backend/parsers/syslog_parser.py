"""Syslog parser (RFC3164-style) with SSH/auth/DNS/DHCP/firewall subtype logic."""

import re

from parsers.registry import register_line

SYSLOG_RX = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-.]+)(?:\[(?P<pid>\d+)\])?:?\s*(?P<msg>.*)$"
)

SSH_FAILED = re.compile(r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
SSH_ACCEPT = re.compile(r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
SUDO_RX = re.compile(r"^\s*(?P<user>\S+)\s*:\s.*COMMAND=(?P<cmd>.*)$")
UFW_RX = re.compile(r"\[?(?P<action>UFW\s+(?:BLOCK|ALLOW|AUDIT))\]?.*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:.*?DPT=(?P<dpt>\d+))?")
DNS_RX = re.compile(r"query:\s+(?P<domain>[\w.\-]+)")
DHCP_RX = re.compile(r"DHCP(?P<kind>DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE)")


@register_line("syslog")
def parse_line(line: str) -> dict | None:
    m = SYSLOG_RX.match(line)
    if not m:
        return None
    msg = m.group("msg") or ""
    fields = {
        "ts_raw": f"{m.group('month')} {m.group('day')} {m.group('time')}",
        "hostname": m.group("host"),
        "source": m.group("proc"),
        "message": msg,
        "event_type": "generic_syslog",
        "_pid": m.group("pid"),
    }

    proc = (m.group("proc") or "").lower()
    sm = SSH_FAILED.search(msg)
    if sm:
        fields.update(event_type="auth_failure", username=sm.group("user"),
                      src_ip=sm.group("ip"), action="failed", status="failure")
        return fields
    sa = SSH_ACCEPT.search(msg)
    if sa:
        fields.update(event_type="auth_success", username=sa.group("user"),
                      src_ip=sa.group("ip"), action="accepted", status="success")
        return fields
    if proc == "sshd" or " sshd" in msg[:20]:
        if "Invalid user" in msg:
            fields.update(event_type="auth_failure", action="failed", status="failure")
            iu = re.search(r"Invalid user (\S+) from (\S+)", msg)
            if iu:
                fields["username"] = iu.group(1)
                fields["src_ip"] = iu.group(2)
            return fields
    su = SUDO_RX.match(msg)
    if proc == "sudo" and su:
        fields.update(event_type="privilege_escalation", username=su.group("user"),
                      command_line=su.group("cmd").strip(), status="success")
        return fields
    um = UFW_RX.search(msg)
    if um:
        fields.update(event_type="firewall_event", action=um.group("action").split()[-1].lower(),
                      status=um.group("action").split()[-1].lower(), protocol=um.group("proto"))
        if um.group("src"):
            fields["src_ip"] = um.group("src")
        if um.group("dst"):
            fields["dst_ip"] = um.group("dst")
        if um.group("dpt"):
            fields["dst_port"] = int(um.group("dpt"))
        return fields
    dm = DNS_RX.search(msg)
    if dm and proc in ("named", "dnsmasq", "resolved"):
        fields.update(event_type="dns_query", domain=dm.group("domain"))
        return fields
    hm = DHCP_RX.search(msg)
    if hm:
        fields.update(event_type="dhcp_event", action=hm.group("kind").lower())
        ipm = re.search(r"via (\d{1,3}(?:\.\d{1,3}){3})|\bfor (\d{1,3}(?:\.\d{1,3}){3})", msg)
        if ipm:
            fields["dst_ip"] = ipm.group(1) or ipm.group(2)
        return fields
    if "authentication failure" in msg or "FAILED" in msg or "fail" in msg.lower():
        fields.update(event_type="auth_failure", status="failure", action="failed")
    return fields
