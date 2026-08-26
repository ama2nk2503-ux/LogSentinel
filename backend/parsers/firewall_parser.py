"""Key=Value firewall parser, Suricata/Snort IDS parser, Squid proxy parser."""

import re

from parsers.registry import register_line

KV_PAIR = re.compile(r"\b([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|[^\s]+)")

CANON = {
    "src": "src_ip", "SRC": "src_ip", "src_ip": "src_ip", "source_ip": "src_ip", "sip": "src_ip",
    "dst": "dst_ip", "DST": "dst_ip", "dst_ip": "dst_ip", "destination_ip": "dst_ip", "dip": "dst_ip",
    "sport": "src_port", "SPORT": "src_port", "src_port": "src_port",
    "dport": "dst_port", "DPORT": "dst_port", "dst_port": "dst_port", "DPT": "dst_port", "port": "dst_port",
    "proto": "protocol", "PROTO": "protocol", "protocol": "protocol",
    "action": "action", "ACTION": "action", "outcome": "action",
    "user": "username", "USER": "username", "username": "username",
    "iface": "interface", "IN": "interface_in", "OUT": "interface_out",
}
DENY_WORDS = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject"}
ALLOW_WORDS = {"allow", "allowed", "accept", "accepted", "permit", "pass"}

SURICATA_RX = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)?\s*\[\*\*\]\s*"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.+?)\s*\[\*\*\]"
    r"(?:\s*\[Classification:\s*(?P<class>[^\]]*)\])?"
    r"(?:\s*\[Priority:\s*(?P<prio>\d+)\])?\s*\{?(?P<proto>[A-Z]+)}?\s*"
    r"(?P<src>[\d.]+):?(?P<sport>\d+)?\s*->\s*(?P<dst>[\d.]+):?(?P<dport>\d+)?"
)
SQUID_RX = re.compile(
    r"^(?P<epoch>\d{9,12})\.(?P<ms>\d{3})\s+(?P<dur>\d+)\s+(?P<src>[\d.]+)\s+"
    r"(?P<code>TCP_\w+|NONE_\w+)/(?P<status>\d{3})\s+(?P<bytes>\d+)\s+"
    r"(?P<method>\w+)\s+(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<hier>\S+)\s+(?P<mime>\S+)"
)


@register_line("firewall")
def parse_kv_line(line: str) -> dict | None:
    pairs = KV_PAIR.findall(line)
    net_pairs = [(k, v) for k, v in pairs if k in CANON]
    if not pairs or len(net_pairs) < 2:
        return None
    fields = {
        "event_type": "firewall_event",
        "message": line,
    }
    for k, v in net_pairs:
        canon = CANON[k]
        val = v.strip('"')
        if canon.endswith("_port"):
            try:
                val = int(val)
            except ValueError:
                continue
        if fields.get(canon) is None or canon == "action":
            fields[canon] = val
    act = str(fields.get("action", "")).lower()
    if any(w in act for w in DENY_WORDS):
        fields["status"] = "deny"
    elif any(w in act for w in ALLOW_WORDS):
        fields["status"] = "allow"
    return fields


@register_line("suricata")
def parse_suricata_line(line: str) -> dict | None:
    m = SURICATA_RX.search(line)
    if not m:
        return None
    prio = m.group("prio")
    fields = {
        "ts_raw": m.group("ts"),
        "event_type": "ids_alert",
        "signature_id": f"{m.group('gid')}:{m.group('sid')}:{m.group('rev')}",
        "message": (m.group("msg") or "").strip(),
        "protocol": (m.group("proto") or "").lower(),
        "src_ip": m.group("src"),
        "dst_ip": m.group("dst"),
        "classification": m.group("class"),
        "severity_hint": {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "LOW"),
        "action": "alert",
    }
    if m.group("sport"):
        fields["src_port"] = int(m.group("sport"))
    if m.group("dport"):
        fields["dst_port"] = int(m.group("dport"))
    return fields


@register_line("proxy")
def parse_squid_line(line: str) -> dict | None:
    m = SQUID_RX.match(line)
    if not m:
        return None
    code = m.group("code")
    fields = {
        "ts_raw": m.group("epoch") + "." + m.group("ms"),
        "event_type": "proxy_request",
        "src_ip": m.group("src"),
        "url": m.group("url"),
        "http_method": m.group("method"),
        "status": m.group("status"),
        "bytes_sent": int(m.group("bytes")),
        "username": None if m.group("user") == "-" else m.group("user"),
        "duration_ms": int(m.group("dur")),
        "action": "deny" if "DENIED" in code else "allow",
        "message": line,
    }
    return fields
