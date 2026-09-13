"""Named vendor parsers (M4): Cisco ASA, Fortinet, Palo Alto PAN-OS,
Check Point, AWS CloudTrail JSON, Okta system-log JSON, CrowdStrike Falcon
JSON, DNS query logs, and an OT/industrial key=value sensor log.

Every parser is ADDITIVE: registered alongside the existing syslog/apache/
windows/firewall/structured parsers without modifying them. Field mappings
are documented per parser and deterministic — no heuristics beyond the
formats below.
"""

import json
import re

from parsers.registry import register_line

IPV4_RX = r"(?:\d{1,3}\.){3}\d{1,3}"


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Cisco ASA: %ASA-SEVERITY-ID: ...  (also %FTD- / %FPR- share the shape)
# e.g. %ASA-6-302013: Built inbound TCP connection 1 for outside:1.2.3.4/5000
# ---------------------------------------------------------------------------
ASA_RX = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>\d?\s*)?"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?"   # optional RFC3164 stamp
    r"%(?P<prod>ASA|FTD|FPR)-(?P<sev>\d)-(?P<code>\d{6}):?\s*(?P<msg>.*)$")
ASA_BUILT = re.compile(
    r"Built (?:inbound|outbound) (?P<proto>[A-Z]+) connection \d+ for "
    r"(?P<if_out>\w+):(?P<dst>" + IPV4_RX + r")/(?P<dport>\d+)"
    r"(?:\s+\(" + IPV4_RX + r"/\d+\))? to "
    r"(?P<if_in>\w+):(?P<src>" + IPV4_RX + r")/(?P<sport>\d+)")
ASA_STAMP = re.compile(r"^(?:<\d{1,3}>\d?\s*)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
ASA_TEARDOWN = re.compile(
    r"Teardown (?P<proto>[A-Z]+) connection \d+ for "
    r"(?P<if_out>\w+):(?P<dst>" + IPV4_RX + r")/(?P<dport>\d+) to "
    r"(?P<if_in>\w+):(?P<src>" + IPV4_RX + r")/(?P<sport>\d+)"
    r"(?: duration \S+ bytes \d+)? ?(?P<reason>.*)")
ASA_DENY = re.compile(
    r"(?:Deny|denied)(?:\s+(?:inbound|outbound))? (?P<proto>[A-Z]+?)"
    r"(?:\s+\(no connection\))? from "
    r"(?P<src>" + IPV4_RX + r")/(?P<sport>\d+) to "
    r"(?P<dst>" + IPV4_RX + r")/(?P<dport>\d+)", re.I)
ASA_AUTH_FAIL = re.compile(
    r"(?P<kind>authentication|login) (?P<action>failed|rejected) from "
    r"(?P<src>" + IPV4_RX + r")(?: to \S+)?(?: for user \"?(?P<user>[^\"]+)\"?)?", re.I)
ASA_SEV = {"0": "CRITICAL", "1": "CRITICAL", "2": "HIGH", "3": "HIGH",
           "4": "MEDIUM", "5": "MEDIUM", "6": "LOW", "7": "LOW"}


@register_line("cisco_asa")
def parse_cisco_asa_line(line: str) -> dict | None:
    stripped = line.strip()
    stamp = ASA_STAMP.match(stripped)
    if stamp:
        stripped = stripped[stamp.end():]
        stripped = re.sub(r"^[\w.\-]+\s+", "", stripped, count=1)  # optional host
    if not stripped.startswith("%"):
        return None
    m = ASA_RX.match(stripped)
    if not m:
        return None
    code = m.group("code")
    msg = m.group("msg")
    fields = {
        "source": f"cisco-{m.group('prod').lower()}",
        "severity_hint": ASA_SEV.get(m.group("sev"), "LOW"),
        "event_code": code,
        "message": line,
    }
    if stamp:
        fields["ts_raw"] = stamp.group(1)
    for rx, f in ((ASA_BUILT, "asa_built"), (ASA_TEARDOWN, "asa_teardown"),
                  (ASA_DENY, "asa_deny"), (ASA_AUTH_FAIL, "asa_auth")):
        sm = rx.search(msg)
        if sm:
            fields["_rx"] = f
            break
    else:
        sm = None
    if sm is None:
        return fields
    g = sm.groupdict()
    fields["protocol"] = (g.get("proto") or "").lower() or fields.get("protocol")
    fields["src_ip"] = g.get("src")
    fields["dst_ip"] = g.get("dst")
    fields["src_port"] = _int_or_none(g.get("sport"))
    fields["dst_port"] = _int_or_none(g.get("dport"))
    if fields["_rx"] == "asa_auth":
        fields.update(event_type="auth_failure", action="failed", status="failure")
        if g.get("user"):
            fields["username"] = g["user"]
    elif fields["_rx"] == "asa_deny":
        fields.update(event_type="firewall_event", action="deny", status="deny")
    elif fields["_rx"] == "asa_built":
        fields.update(event_type="firewall_event", action="allow", status="allow")
    else:
        fields.update(event_type="firewall_event", action="connection_teardown")
    return fields


# ---------------------------------------------------------------------------
# Fortinet FortiGate key=value: date=2026-08-25 time=10:30:01 devname=FW1
#   action=deny srcip=1.2.3.4 dstip=5.6.7.8 dstport=22 proto=6
# ---------------------------------------------------------------------------
FTG_KV = re.compile(r"\b([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|[^\s]+)")
FTG_CANON = {
    "srcip": "src_ip", "dstip": "dst_ip", "srcport": "src_port",
    "dstport": "dst_port", "proto": "protocol", "action": "action",
    "user": "username", "devname": "hostname", "hostname": "domain",
    "url": "url", "level": "level",
}
FTG_DENY = {"deny", "blocked", "drop", "reset", "ip-blocklist"}
FTG_ALLOW = {"accept", "forward", "start", "close", "client-rst"}


@register_line("fortinet")
def parse_fortinet_line(line: str) -> dict | None:
    if "devname=" not in line and "vd=" not in line:
        return None
    pairs = FTG_KV.findall(line)
    if not pairs:
        return None
    kv = {k: v.strip('"') for k, v in pairs}
    if "srcip" not in kv and "dstip" not in kv and "action" not in kv:
        return None
    date_s = kv.get("date", "")
    time_s = kv.get("time", "")
    fields = {
        "event_type": "firewall_event",
        "message": line,
        "hostname": kv.get("devname", ""),
        "event_code": kv.get("subtype", ""),
    }
    if date_s and time_s:
        fields["ts_raw"] = f"{date_s} {time_s}"
    elif date_s:
        fields["ts_raw"] = date_s
    for k, canon in FTG_CANON.items():
        if k in kv and kv[k] not in ("", "N/A"):
            if canon.endswith("_port"):
                val = _int_or_none(kv[k])
                if val is not None:
                    fields[canon] = val
            else:
                fields[canon] = kv[k]
    if fields.get("protocol", "").isdigit():
        fields["protocol"] = {"6": "tcp", "17": "udp", "1": "icmp",
                              "47": "gre"}.get(fields["protocol"], fields["protocol"])
    if "logid" in kv:
        fields["event_code"] = kv["logid"]
    act = (kv.get("action") or "").lower()
    if act in FTG_DENY:
        fields["status"] = "deny"
    elif act in FTG_ALLOW:
        fields["status"] = "allow"
    if (kv.get("level") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        fields["severity_hint"] = kv["level"].upper()
    return fields


# ---------------------------------------------------------------------------
# Palo Alto PAN-OS (syslog LEEF-ish CSV): <13>1 date host -- type subtype ||
#   e.g. <13>1 2026-08-25T10:30:01+00:00 PA-FW - - TRAFFIC,allow,1.2.3.4,...
# ---------------------------------------------------------------------------
PANOS_HEADER = re.compile(
    r"^(?:<\d{1,3}>\d?\s*)?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+\S*\s+\S*\s+")
PANOS_TYPES = ("TRAFFIC", "THREAT", "AUTHENTICATION", "SYSTEM", "CONFIG", "GLOBALPROTECT")


@register_line("palo_alto")
def parse_panos_line(line: str) -> dict | None:
    body = line
    m = PANOS_HEADER.match(line)
    ts, host = None, ""
    if m:
        ts, host = m.group("ts"), m.group("host")
        body = line[m.end():]
    body = body.lstrip(", ")
    parts = [p.strip() for p in body.split(",")]
    if not parts or parts[0].upper() not in PANOS_TYPES:
        return None
    ltype = parts[0].upper()
    fields = {
        "source": "pan-os",
        "hostname": host,
        "message": line,
        "event_code": ltype,
    }
    if ts:
        fields["ts_raw"] = ts
    # Column contract: type,action,src,dst,sport,dport,protocol[,domain|url[,threat]]
    if ltype in ("TRAFFIC", "THREAT") and len(parts) >= 5:
        action = parts[1].lower()
        fields.update(src_ip=parts[2] if IPV4_FULL.match(parts[2]) else None,
                      dst_ip=parts[3] if IPV4_FULL.match(parts[3]) else None,
                      event_type="firewall_event" if ltype == "TRAFFIC" else "ids_alert",
                      action=action)
        for idx, key in ((4, "src_port"), (5, "dst_port")):
            if len(parts) > idx:
                val = _int_or_none(parts[idx])
                if val is not None:
                    fields[key] = val
        if len(parts) > 6 and parts[6] and not parts[6].isdigit():
            fields["protocol"] = parts[6].lower()
        if len(parts) > 7 and parts[7] and parts[7].lower() not in ("-", "any"):
            fields["domain"] = parts[7].rstrip("/").lower()
        if len(parts) > 8 and parts[8] and parts[8].lower() not in ("-", "any"):
            fields["threat_name"] = parts[8]
            fields["severity_hint"] = "HIGH"
        if action in ("deny", "deny-ip", "drop", "reset-both", "block-url"):
            fields["status"] = "deny"
        elif action in ("allow", "alert"):
            fields["status"] = "allow"
    elif ltype == "AUTHENTICATION" and len(parts) >= 4:
        fields.update(event_type="auth_failure" if parts[1].lower() in (
            "auth-fail", "deny") else "auth_success",
            action=parts[1].lower(), status="failure" if fields["event_type"] == "auth_failure" else "success")
        if len(parts) > 2:
            fields["username"] = parts[2]
        if len(parts) > 3 and IPV4_FULL.match(parts[3]):
            fields["src_ip"] = parts[3]
    else:
        fields["event_type"] = "generic_syslog"
        if len(parts) > 1:
            fields["action"] = parts[1].lower()
    return fields


IPV4_FULL = re.compile(r"^" + IPV4_RX + r"$")


# ---------------------------------------------------------------------------
# Check Point (syslog product line): <pri>date fw product=VPN-1; ...
#   action=Accept src=1.2.3.4 dst=5.6.7.8 service=443 proto=tcp
# ---------------------------------------------------------------------------
CP_HDR = re.compile(r"^(?:<\d{1,3}>\d?\s*)?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
                    r"?\s*(?P<host>\S*)\s*product=\S+;\s*", re.I)


@register_line("check_point")
def parse_check_point_line(line: str) -> dict | None:
    if "product=" not in line:
        return None
    pairs = dict(FTG_KV.findall(line))
    if "product" not in pairs and "product=" not in line:
        return None
    m = CP_HDR.match(line)
    fields = {
        "source": "check-point",
        "message": line,
        "event_type": "firewall_event",
    }
    if m:
        if m.group("ts"):
            fields["ts_raw"] = m.group("ts").replace("T", " ")
        if m.group("host"):
            fields["hostname"] = m.group("host")
    CANON = {
        "src": "src_ip", "dst": "dst_ip", "sport": "src_port", "service": "dst_port",
        "s_port": "src_port", "proto": "protocol", "action": "action", "user": "username",
    }
    for k, canon in CANON.items():
        v = pairs.get(k)
        if v in (None, "", "N/A"):
            continue
        v = v.strip('"').rstrip(";")
        if canon.endswith("_port"):
            val = _int_or_none(v)
            if val is not None:
                fields[canon] = val
        else:
            fields[canon] = v
    act = (fields.get("action") or "").lower()
    if act in ("drop", "reject", "block"):
        fields["status"] = "deny"
    elif act in ("accept", "allow"):
        fields["status"] = "allow"
    return fields


# ---------------------------------------------------------------------------
# AWS CloudTrail JSON (one record per line)
# ---------------------------------------------------------------------------
CT_EVENT_SOURCES = ("ec2", "iam", "s3", "sts", "console", "cloudtrail", "kms", "lambda")


@register_line("cloudtrail")
def parse_cloudtrail_line(line: str) -> dict | None:
    s = line.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        rec = json.loads(s)
    except ValueError:
        return None
    if not isinstance(rec, dict) or "eventSource" not in rec or "eventName" not in rec:
        return None
    src = str(rec.get("eventSource", "")).split(".")[0].lower()
    if src not in CT_EVENT_SOURCES:
        return None
    ident = rec.get("userIdentity") or {}
    fields = {
        "event_type": "cloud_event",
        "source": f"aws-{src}",
        "event_code": rec.get("eventName"),
        "message": json.dumps(rec)[:1000],
        "username": (ident.get("arn") or ident.get("principalId") or
                     (ident.get("sessionContext", {}).get("sessionIssuer", {}) or {}).get("arn", "")),
        "severity_hint": "HIGH" if rec.get("error") or rec.get("errorCode") else "LOW",
    }
    ts = rec.get("eventTime")
    if ts:
        fields["ts_raw"] = ts
    r = rec.get("requestParameters") or {}
    rip = r.get("sourceIPAddress") or r.get("ipAddress") or rec.get("sourceIPAddress")
    if isinstance(rip, str) and IPV4_FULL.match(rip):
        fields["src_ip"] = rip
    if isinstance(r.get("instanceId"), str):
        fields["resource"] = r["instanceId"]
    if rec.get("errorCode"):
        fields["action"] = "error"
        fields["status"] = "failure"
    return fields


# ---------------------------------------------------------------------------
# Okta system-log JSON
# ---------------------------------------------------------------------------
OKTA_OUTCOMES_FAIL = {"FAILURE", "DENY", "CHALLENGE_FAILED", "UNKNOWN"}


@register_line("okta")
def parse_okta_line(line: str) -> dict | None:
    s = line.strip()
    if not s.startswith("{"):
        return None
    try:
        rec = json.loads(s)
    except ValueError:
        return None
    if not isinstance(rec, dict) or "eventType" not in rec or "uuid" not in rec:
        return None
    outcome = (rec.get("outcome") or {})
    result = str(outcome.get("result", "")).upper()
    actor = rec.get("actor") or {}
    client = rec.get("client") or {}
    fields = {
        "event_type": "cloud_event",
        "source": "okta",
        "event_code": rec.get("eventType"),
        "message": rec.get("displayMessage") or rec.get("eventType") or "",
        "username": actor.get("displayName") or actor.get("alternateId"),
        "action": result.lower() or None,
        "status": "failure" if result in OKTA_OUTCOMES_FAIL else "success",
        "severity_hint": "MEDIUM" if result in OKTA_OUTCOMES_FAIL else "LOW",
    }
    ts = rec.get("published")
    if ts:
        fields["ts_raw"] = ts
    ip = client.get("ipAddress")
    if isinstance(ip, str) and IPV4_FULL.match(ip):
        fields["src_ip"] = ip
    ua = client.get("userAgent")
    if isinstance(ua, dict) and ua.get("rawUserAgent"):
        fields["user_agent"] = ua["rawUserAgent"]
    tgt = rec.get("target") or []
    if tgt and isinstance(tgt[0], dict) and tgt[0].get("type") == "AppUser":
        fields["resource"] = tgt[0].get("displayName")
    return fields


# ---------------------------------------------------------------------------
# CrowdStrike Falcon JSON
# ---------------------------------------------------------------------------
CS_SEV = {0: "LOW", 1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}


@register_line("crowdstrike")
def parse_crowdstrike_line(line: str) -> dict | None:
    s = line.strip()
    if not s.startswith("{"):
        return None
    try:
        rec = json.loads(s)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    if not any(k in rec for k in ("event_type", "detection_id", "cid")):
        return None
    meta = rec.get("metadata") or {}
    sevx = meta.get("event_score", rec.get("severity", 0))
    fields = {
        "event_type": "edr_event",
        "source": "crowdstrike-falcon",
        "event_code": rec.get("event_type") or "detection",
        "message": rec.get("description") or rec.get("name") or rec.get("event_type") or "",
        "severity_hint": CS_SEV.get(int(sevx) if str(sevx).isdigit() else 0, "LOW"),
        "hostname": rec.get("hostname") or rec.get("device_hostname") or "",
    }
    if rec.get("detection_id"):
        fields["detection_ref"] = rec["detection_id"]
    ts = rec.get("timestamp") or rec.get("event_created")
    if ts:
        fields["ts_raw"] = ts
    for k in ("local_ip", "device_ip", "remote_ip"):
        v = rec.get(k)
        if isinstance(v, str) and IPV4_FULL.match(v):
            fields.setdefault("src_ip", v)
    for k in ("remote_ip", "destination_ip"):
        v = rec.get(k)
        if isinstance(v, str) and IPV4_FULL.match(v):
            fields["dst_ip"] = v
    if rec.get("command_line"):
        fields["command_line"] = rec["command_line"]
        fields["severity_hint"] = "HIGH" if any(
            w in rec["command_line"].lower() for w in ("-enc", "whoami", "net user")) else fields["severity_hint"]
    user = rec.get("username") or rec.get("user_name")
    if user:
        fields["username"] = user
    if fields["severity_hint"] in ("HIGH", "CRITICAL"):
        fields["action"] = "detect"
        fields["status"] = "failure"    # EDR flagged behavior
    return fields


# ---------------------------------------------------------------------------
# DNS query logs (bind/dnsmasq style): "query: example.com IN A +"
#   plus generic "client 1.2.3.4 query: ..." shapes.
# ---------------------------------------------------------------------------
DNS_Q_RX = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?\s*(?P<host>[\w.\-]+)?\s*"
    r"(?:\[\d+\])?\s*(?:client\s+(?P<client>" + IPV4_RX + r")(?:#\d+)?:?\s*)?"
    r"query(?:[:\s]+|:\s*)(?P<domain>[A-Za-z0-9][\w.\-]*)\s+(?:IN\s+)?(?P<qtype>[A-Z]+)", re.I)


@register_line("dns")
def parse_dns_line(line: str) -> dict | None:
    if "query" not in line.lower():
        return None
    m = DNS_Q_RX.search(line)
    if not m or not m.group("domain"):
        return None
    fields = {
        "event_type": "dns_query",
        "source": "dns",
        "domain": m.group("domain").rstrip(".").lower(),
        "query_type": (m.group("qtype") or "").upper(),
        "message": line,
    }
    if m.group("ts"):
        fields["ts_raw"] = m.group("ts")
    if m.group("host"):
        fields["hostname"] = m.group("host")
    if m.group("client"):
        fields["src_ip"] = m.group("client")
    return fields


# ---------------------------------------------------------------------------
# OT / industrial key=value sensor log
#   ts=2026-08-25T10:30:01Z plc=PLC-01 tag=TEMP_101 value=87.4 unit=C status=NORMAL
# ---------------------------------------------------------------------------
OT_SEV = {"FAIL", "ERR", "ERROR", "ALARM", "TRIP", "CRITICAL", "EMERGENCY"}


@register_line("ot_sensor")
def parse_ot_sensor_line(line: str) -> dict | None:
    if "=" not in line:
        return None
    pairs = dict(FTG_KV.findall(line))
    if not pairs:
        return None
    lowered = {k.lower(): v for k, v in pairs.items()}
    tag = lowered.get("tag") or lowered.get("sensor") or lowered.get("point")
    plc = lowered.get("plc") or lowered.get("device") or lowered.get("controller")
    if not tag and not plc:
        return None
    status = (lowered.get("status") or lowered.get("state") or "").upper()
    fields = {
        "event_type": "ot_sensor_event",
        "source": plc or "ot-sensor",
        "message": line,
        "ot_tag": tag or "",
        "ot_value": lowered.get("value", ""),
        "ot_unit": lowered.get("unit", ""),
        "action": status.lower() or None,
        "status": "failure" if status in OT_SEV else "success",
        "severity_hint": "HIGH" if status in OT_SEV else "LOW",
    }
    ts = lowered.get("ts") or lowered.get("timestamp") or lowered.get("time")
    if ts:
        fields["ts_raw"] = ts
    if plc:
        fields["hostname"] = plc
    return fields
