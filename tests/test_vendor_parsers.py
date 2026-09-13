"""M4: named vendor parser tests — one per added parser, plus detection,
normalization and end-to-end rule firing. All parsers are additive; the
existing syslog/apache/windows/firewall parsers are untouched.
"""

import json

from normalization.normalizer import normalize
from parsers.load_all import *  # noqa: F401,F403 — registers all parsers
from parsers.detector import detect_format
from parsers.firewall_parser import parse_kv_line
from parsers.registry import get_file_handler, get_line_parser
from parsers.vendor_parsers import (parse_check_point_line, parse_cisco_asa_line,
                                    parse_cloudtrail_line, parse_crowdstrike_line,
                                    parse_dns_line, parse_fortinet_line,
                                    parse_okta_line, parse_ot_sensor_line,
                                    parse_panos_line)
from parsers.vendor_structured import _iter_json_records
from parsers.vmware_esxi_parser import parse_esxi_line
from parsers.vmware_nsx_parser import parse_nsx_line
from parsers.vmware_vcenter_parser import parse_vcenter_line
from tests.test_detection import insert_event

ASA_DENY = "%ASA-4-401004: Denied inbound TCP from 185.23.45.67/1234 to 10.0.0.15/443"
ASA_BUILT = "%ASA-6-302013: Built inbound TCP connection 1 for outside:1.2.3.4/5000 to inside:10.0.0.15/22"
FORTINET_DENY = ("date=2026-08-25 time=10:30:01 devname=FW1 logid=0000000013 "
                 "action=deny srcip=185.23.45.67 dstip=10.0.0.15 dstport=22 proto=6")
PANOS_TRAFFIC = "2026-08-25T10:30:01+00:00 PA-FW - - TRAFFIC,deny,185.23.45.67,10.0.0.15,1234,22,tcp,-,-"
PANOS_THREAT = ("2026-08-25T10:30:01+00:00 PA-FW - - THREAT,alert,185.23.45.67,10.0.0.15,"
                "1234,443,tcp,evil.example.com,suspect-download")
CHECKPOINT_DROP = ("10:30:01 fw01 product=VPN-1; action=drop src=185.23.45.67 "
                   "dst=10.0.0.15 service=22 proto=tcp")
CLOUDTRAIL = json.dumps({
    "eventTime": "2026-08-25T10:30:01Z", "eventSource": "iam.amazonaws.com",
    "eventName": "CreateUser", "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
    "sourceIPAddress": "185.23.45.67",
})
OKTA_FAIL = json.dumps({
    "published": "2026-08-25T10:30:01Z", "eventType": "user.session.start",
    "uuid": "abc-123", "displayMessage": "User sign-in fail",
    "actor": {"displayName": "bob@x.com"}, "client": {"ipAddress": "185.23.45.67"},
    "outcome": {"result": "FAILURE"},
})
CROWDSTRIKE = json.dumps({
    "event_type": "DetectionSummaryEvent", "detection_id": "ldt:abc", "cid": "c1",
    "severity": 4, "hostname": "WS01", "command_line": "powershell -enc AAA",
    "local_ip": "10.0.0.15", "remote_ip": "185.23.45.67",
    "timestamp": "2026-08-25T10:30:01Z",
})
DNS_QUERY = "Aug 25 10:30:01 dns01 named[31101]: client 185.23.45.67#5353: query: verylonglabelaa.evil.example IN AAAA +"
OT_ALARM = "ts=2026-08-25T10:30:01Z plc=PLC-01 tag=TEMP_101 value=612.5 unit=C status=ALARM"
ESXI_FAIL = ("2026-09-12T14:30:01.482Z hostd[2358721] [originator@6876 sub=AccountLocker "
             "opID=207602-3E51] Failed login for user 'admin' from 185.23.45.67")
ESXI_LOCK = ("2026-09-12T14:30:02.482Z hostd[2358721] [originator@6876 sub=AccountLocker] "
             "user 'admin' was locked out after 5 failed login attempts")
ESXI_OK = ("2026-09-12T14:31:00.482Z hostd[2358721] [originator@6876 sub=AccountLocker] "
           "Authenticated user 'admin' from 192.168.1.10")
NSX_DROP = "2026-09-12T14:30:01Z [Firewall] [10547] [INFO] block UDP from 10.99.0.31:53123 to 10.0.0.1:53"
NSX_AUDIT_OK = ("2026-09-12T14:30:01Z nsxmanager 105337 audit: user 'alice' [type: USER] "
                "role 'ENTERPRISE_ADMIN' authenticated successfully from 10.0.0.1")
NSX_AUDIT_FAIL = ("2026-09-12T14:30:02Z nsxmanager 105338 audit: user 'alice' [type: USER] "
                  "failed to authenticate from 10.0.0.1")
VC_AUTH_OK = "2026-09-12T14:30:01.123Z audit vpxd[06870] user 'root' Authenticated from 192.168.1.10"
VC_AUTH_FAIL = "2026-09-12T14:30:02.123Z audit vpxd[06870] user 'root' Failed to authenticate from 192.168.1.10"
VC_LOCK = "2026-09-12T14:30:03.123Z audit vpxd[06870] user 'root' Lockout state triggered"


# ---------- per-parser unit tests ----------

def test_cisco_asa_deny():
    f = parse_cisco_asa_line(ASA_DENY)
    assert f and f["event_type"] == "firewall_event"
    assert f["src_ip"] == "185.23.45.67" and f["dst_ip"] == "10.0.0.15"
    assert f["dst_port"] == 443 and f["status"] == "deny"
    assert f["severity_hint"] == "MEDIUM"          # ASA severity 4


def test_cisco_asa_built_and_auth_fail():
    f = parse_cisco_asa_line(ASA_BUILT)
    assert f["status"] == "allow" and f["protocol"] == "tcp"
    f2 = parse_cisco_asa_line('%ASA-6-113005: AAA authentication rejected for user "bob" from 185.23.45.67')
    assert f2 is not None and f2["event_code"] == "113005"
    assert parse_cisco_asa_line("plain line without ASA tag") is None


def test_fortinet_kv():
    f = parse_fortinet_line(FORTINET_DENY)
    assert f and f["event_type"] == "firewall_event"
    assert f["src_ip"] == "185.23.45.67" and f["dst_port"] == 22
    assert f["protocol"] == "tcp"                  # proto=6 mapped
    assert f["status"] == "deny" and f["hostname"] == "FW1"
    assert f["ts_raw"] == "2026-08-25 10:30:01"


def test_palo_alto_traffic_and_threat():
    f = parse_panos_line(PANOS_TRAFFIC)
    assert f["event_type"] == "firewall_event" and f["status"] == "deny"
    assert f["src_ip"] == "185.23.45.67" and f["dst_port"] == 22
    t = parse_panos_line(PANOS_THREAT)
    assert t["event_type"] == "ids_alert"
    assert t["domain"] == "evil.example.com" and t["severity_hint"] == "HIGH"
    assert parse_panos_line("random,text,not,panos") is None


def test_check_point_drop():
    f = parse_check_point_line(CHECKPOINT_DROP)
    assert f and f["event_type"] == "firewall_event"
    assert f["src_ip"] == "185.23.45.67" and f["dst_port"] == 22
    assert f["status"] == "deny" and f["source"] == "check-point"
    assert parse_check_point_line("no product marker here src=1.2.3.4") is None


def test_cloudtrail_record():
    f = parse_cloudtrail_line(CLOUDTRAIL)
    assert f and f["event_type"] == "cloud_event"
    assert f["source"] == "aws-iam" and f["username"].endswith("/bob")
    assert f["src_ip"] == "185.23.45.67"
    assert parse_cloudtrail_line(json.dumps({"foo": 1})) is None


def test_okta_failure_outcome():
    f = parse_okta_line(OKTA_FAIL)
    assert f and f["event_type"] == "cloud_event"
    assert f["status"] == "failure" and f["severity_hint"] == "MEDIUM"
    assert f["src_ip"] == "185.23.45.67" and f["username"] == "bob@x.com"


def test_crowdstrike_detection():
    f = parse_crowdstrike_line(CROWDSTRIKE)
    assert f and f["event_type"] == "edr_event"
    assert f["severity_hint"] == "HIGH"            # severity 4
    assert "-enc" in f["command_line"] and f["hostname"] == "WS01"


def test_dns_query_log():
    f = parse_dns_line(DNS_QUERY)
    assert f and f["event_type"] == "dns_query"
    assert f["domain"] == "verylonglabelaa.evil.example"
    assert f["src_ip"] == "185.23.45.67" and f["query_type"] == "AAAA"
    assert parse_dns_line("no dns activity in this line") is None


def test_ot_sensor_alarm():
    f = parse_ot_sensor_line(OT_ALARM)
    assert f and f["event_type"] == "ot_sensor_event"
    assert f["ot_tag"] == "TEMP_101" and f["status"] == "failure"
    assert f["severity_hint"] == "HIGH" and f["hostname"] == "PLC-01"


# ---------- existing parsers untouched (regression guard) ----------

def test_existing_parsers_still_parse_their_formats():
    assert parse_kv_line("SRC=185.23.45.67 DST=10.0.0.15 PROTO=TCP DPT=443 ACTION=DENY")["status"] == "deny"
    from parsers.syslog_parser import parse_line as parse_syslog
    assert parse_syslog("Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")["event_type"] == "auth_failure"


# ---------- detection ----------

def test_detect_vendor_formats():
    assert detect_format([ASA_DENY, ASA_BUILT])["format"] == "cisco_asa"
    r = detect_format([FORTINET_DENY, FORTINET_DENY.replace("dstport=22", "dstport=80")])
    assert r["format"] == "fortinet" and r["subtype"] == "Fortinet FortiGate"
    assert detect_format([PANOS_TRAFFIC, PANOS_THREAT])["format"] == "palo_alto"
    assert detect_format([CHECKPOINT_DROP, CHECKPOINT_DROP])["format"] == "check_point"
    assert detect_format([DNS_QUERY, DNS_QUERY.replace("verylonglabelaa", "other00labelaa"),
                          DNS_QUERY, DNS_QUERY])["format"] == "dns"
    # JSON vendor flavors resolve to the named vendor, not plain json
    assert detect_format([CLOUDTRAIL, CLOUDTRAIL])["format"] == "cloudtrail"
    assert detect_format([OKTA_FAIL, OKTA_FAIL])["format"] == "okta"
    assert detect_format([CROWDSTRIKE, CROWDSTRIKE])["format"] == "crowdstrike"


# ---------- normalization ----------

def test_vendor_fields_normalize_into_universal_event():
    ASA_STAMPED = "Aug 25 10:30:01 fw %ASA-4-401004: Denied inbound TCP from 185.23.45.67/1234 to 10.0.0.15/443"
    ev = normalize(parse_cisco_asa_line(ASA_STAMPED), "job_v", 1, ASA_STAMPED)
    assert ev.source_ip == "185.23.45.67" and ev.destination_port == 443
    assert ev.severity == "MEDIUM" and ev.timestamp.endswith("Z")
    assert ev.timestamp_source == "event"
    assert ev.event_type == "firewall_event"
    # timestamp-less vendor line keeps ingest provenance
    ev0 = normalize(parse_cisco_asa_line(ASA_DENY), "job_v", 0, ASA_DENY)
    assert ev0.timestamp == "" and ev0.timestamp_source == "ingest"
    ev2 = normalize(parse_cloudtrail_line(CLOUDTRAIL), "job_v", 2, CLOUDTRAIL)
    assert ev2.event_type == "cloud_event" and ev2.username.endswith("/bob")
    assert ev2.timestamp_source == "event"


def test_cloudtrail_file_handler(tmp_path):
    p = tmp_path / "trail.json"
    p.write_text("\n".join([CLOUDTRAIL, OKTA_FAIL]), encoding="utf-8")
    recs = list(get_file_handler("cloudtrail")(p))
    assert len(recs) == 2
    assert recs[0][2]["source"] == "aws-iam"
    p2 = tmp_path / "okta.json"
    p2.write_text("[" + ",".join([OKTA_FAIL, OKTA_FAIL]) + "]", encoding="utf-8")
    recs2 = list(get_file_handler("okta")(p2))
    assert len(recs2) == 2 and recs2[0][2]["event_code"] == "user.session.start"
    assert _iter_json_records(p2)


# ---------- end-to-end rule firing ----------

def _ingest_lines(job_id, lines, fmt_parser):
    for i, ln in enumerate(lines):
        ev = normalize(fmt_parser(ln), job_id, i + 1, ln)
        insert_event(job_id, event_id=ev.event_id, line_no=i + 1, ts=ev.timestamp or None,
                     event_type=ev.event_type, source=ev.source, src_ip=ev.source_ip,
                     dst_ip=ev.destination_ip, src_port=ev.source_port,
                     dst_port=ev.destination_port, protocol=ev.protocol,
                     username=ev.username, hostname=ev.hostname, action=ev.action,
                     status=ev.status, severity=ev.severity, message=ev.message)


DNS_TUNNEL_QUERY = DNS_QUERY.replace("verylonglabelaa", "aaverylonglabelaaaverylonglabelaa")


def test_dns_tunnel_rule_fires_end_to_end():
    from detection.engine import evaluate_job
    job = "t_dns_tunnel"
    lines = [DNS_TUNNEL_QUERY,
             DNS_TUNNEL_QUERY.replace("evil", "evil2"),
             DNS_TUNNEL_QUERY.replace("evil", "evil3"),
             DNS_TUNNEL_QUERY.replace("evil", "evil4"),
             DNS_TUNNEL_QUERY.replace("evil", "evil5")]
    _ingest_lines(job, lines, parse_dns_line)
    dets = [d for d in evaluate_job(job) if d["rule_id"] == "DNS_TUNNEL_001"]
    assert len(dets) == 1
    assert dets[0]["entity"] == "185.23.45.67"


def test_cloud_iam_rule_and_ot_alarm_rule_fire():
    from detection.engine import evaluate_job
    job = "t_cloud_iam"
    _ingest_lines(job, [CLOUDTRAIL] * 5, parse_cloudtrail_line)
    dets = [d for d in evaluate_job(job) if d["rule_id"] == "CLOUD_IAM_001"]
    assert len(dets) == 1

    job2 = "t_ot_alarm"
    _ingest_lines(job2, [OT_ALARM, OT_ALARM.replace("value=612.5", "value=99.1")], parse_ot_sensor_line)
    dets2 = [d for d in evaluate_job(job2) if d["rule_id"] == "OT_ALARM_001"]
    assert len(dets2) == 1
    assert dets2[0]["entity"] == "PLC-01"


def test_edr_malware_rule_fires_for_crowdstrike():
    from detection.engine import evaluate_job
    job = "t_edr"
    _ingest_lines(job, [CROWDSTRIKE] * 2, parse_crowdstrike_line)
    dets = [d for d in evaluate_job(job) if d["rule_id"] == "EDR_MALWARE_001"]
    assert len(dets) == 1
    assert "WS01" in dets[0]["entity"]


# ---------- M5: VMware parsers (esxi / nsx / vcenter) ----------

def test_esxi_failed_login_and_lockout():
    f = parse_esxi_line(ESXI_FAIL)
    assert f and f["event_type"] == "auth_failure"
    assert f["source"] == "vmware-esxi" and f["username"] == "admin"
    assert f["src_ip"] == "185.23.45.67" and f["severity_hint"] == "HIGH"
    lock = parse_esxi_line(ESXI_LOCK)
    assert lock and lock["event_type"] == "auth_failure"
    assert lock["action"] == "lock" and "src_ip" not in lock
    ok = parse_esxi_line(ESXI_OK)
    assert ok["event_type"] == "auth_success" and ok["src_ip"] == "192.168.1.10"
    assert parse_esxi_line("2026-09-12T14:30:01Z some other iso log here") is None


def test_nsx_firewall_and_audit():
    f = parse_nsx_line(NSX_DROP)
    assert f and f["event_type"] == "firewall_event"
    assert f["status"] == "deny" and f["protocol"] == "udp"
    assert f["src_ip"] == "10.99.0.31" and f["dst_port"] == 53
    ok = parse_nsx_line(NSX_AUDIT_OK)
    assert ok["event_type"] == "auth_success" and ok["username"] == "alice"
    assert ok["src_ip"] == "10.0.0.1" and ok["status"] == "success"
    fail = parse_nsx_line(NSX_AUDIT_FAIL)
    assert fail["event_type"] == "auth_failure" and fail["status"] == "failure"
    assert parse_nsx_line("2026-09-12T14:30:01Z random log line") is None


def test_vcenter_authentication_lines():
    ok = parse_vcenter_line(VC_AUTH_OK)
    assert ok and ok["event_type"] == "auth_success"
    assert ok["source"] == "vmware-vcenter" and ok["username"] == "root"
    assert ok["src_ip"] == "192.168.1.10"
    fail = parse_vcenter_line(VC_AUTH_FAIL)
    assert fail["event_type"] == "auth_failure" and fail["severity_hint"] == "HIGH"
    lock = parse_vcenter_line(VC_LOCK)
    assert lock["event_type"] == "auth_failure" and lock["action"] == "lock"
    assert parse_vcenter_line("2026-09-12T14:30:01Z vpxd[9] nothing interesting") is None


def test_detect_vmware_formats():
    assert detect_format([ESXI_FAIL, ESXI_LOCK, ESXI_OK])["format"] == "esxi"
    assert detect_format([NSX_DROP, NSX_AUDIT_OK,
                          NSX_DROP.replace("UDP", "TCP")])["format"] == "nsx"
    assert detect_format([VC_AUTH_OK, VC_AUTH_FAIL, VC_LOCK])["format"] == "vcenter"
    assert get_line_parser("esxi") is parse_esxi_line
    assert get_line_parser("nsx") is parse_nsx_line
    assert get_line_parser("vcenter") is parse_vcenter_line


def test_vmware_fields_normalize():
    ev = normalize(parse_esxi_line(ESXI_FAIL), "job_m5", 1, ESXI_FAIL)
    assert ev.event_type == "auth_failure" and ev.source_ip == "185.23.45.67"
    assert ev.username == "admin" and ev.timestamp_source == "event"
    assert ev.severity == "HIGH"
    ev2 = normalize(parse_nsx_line(NSX_DROP), "job_m5", 2, NSX_DROP)
    assert ev2.event_type == "firewall_event" and ev2.destination_port == 53


def test_vmware_rules_fire_end_to_end():
    from detection.engine import evaluate_job
    job = "t_esxi"
    _ingest_lines(job, [ESXI_FAIL] * 3, parse_esxi_line)
    dets = [d for d in evaluate_job(job) if d["rule_id"] == "VMW_ESXI_LOGIN_BURST_001"]
    assert len(dets) == 1
    assert "185.23.45.67" in dets[0]["entity"]

    job2 = "t_nsx"
    drops = [NSX_DROP.replace(":53", ":%d" % p).replace("UDP", "TCP") for p in
             (22, 80, 443, 445, 3389, 8080)]
    _ingest_lines(job2, drops, parse_nsx_line)
    dets2 = [d for d in evaluate_job(job2) if d["rule_id"] == "VMW_NSX_FIREWALL_SCAN_001"]
    assert len(dets2) == 1
    assert dets2[0]["entity"] == "10.99.0.31"
