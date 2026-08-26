from parsers.detector import detect_format

SYSLOG_SSH = [
    "Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67",
    "Aug 25 10:30:05 server sshd: Failed password for admin from 185.23.45.67",
    "Aug 25 10:30:09 server sshd[4123]: Accepted password for root from 10.0.0.5 port 22 ssh2",
]

APACHE = [
    '185.23.45.67 - - [25/Aug/2026:10:31:02 +0000] "GET /index.php?id=1\' OR 1=1-- HTTP/1.1" 200 1043 "-" "curl/8.0"',
    '10.0.0.9 - admin [25/Aug/2026:10:31:04 +0000] "POST /login HTTP/1.1" 401 210 "http://x/" "Mozilla/5.0"',
]

FIREWALL_KV = [
    "SRC=185.23.45.67 DST=10.0.0.15 PROTO=TCP DPT=443 ACTION=DENY",
    "SRC=185.23.45.67 DST=10.0.0.16 PROTO=TCP DPT=22 ACTION=DENY USER=jdoe",
    "src=192.168.1.7 dst=192.168.1.1 proto=UDP dport=53 action=ALLOW",
]

JSONL = [
    '{"timestamp": "2026-08-25T10:30:12Z", "source_ip": "10.10.2.15", "action": "DENY", "port": 443}',
    '{"timestamp": "2026-08-25T10:30:13Z", "source_ip": "10.10.2.16", "action": "ALLOW", "port": 80}',
    '{"timestamp": "2026-08-25T10:30:14Z", "source_ip": "10.10.2.17", "action": "DENY", "port": 22}',
]

CSV = [
    "timestamp,src_ip,dst_ip,action,port",
    "2026-08-25T10:30:12Z,10.10.2.15,8.8.8.8,DENY,443",
    "2026-08-25T10:30:13Z,10.10.2.16,1.1.1.1,DENY,53",
    "2026-08-25T10:30:14Z,10.10.2.17,9.9.9.9,DENY,80",
]

WINDOWS_XML = [
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
    '  <System>',
    '    <Provider Name="Microsoft-Windows-Security-Auditing"/>',
    '    <EventID>4625</EventID>',
    '    <Level>0</Level>',
    '    <TimeCreated SystemTime="2026-08-25T10:40:01.000Z"/>',
    '    <Computer>DC01.corp.local</Computer>',
    '  </System>',
    '</Event>',
]


def test_detect_syslog_ssh_with_subtype():
    r = detect_format(SYSLOG_SSH)
    assert r["format"] == "syslog"
    assert r["subtype"] == "Linux SSH / Syslog"
    assert r["confidence"] >= 0.85


def test_detect_apache():
    r = detect_format(APACHE)
    assert r["format"] == "apache"
    assert r["confidence"] >= 0.85


def test_detect_firewall_kv():
    r = detect_format(FIREWALL_KV)
    assert r["format"] == "firewall"
    assert r["confidence"] >= 0.6


def test_detect_json_lines():
    r = detect_format(JSONL)
    assert r["format"] == "json"
    assert r["confidence"] >= 0.6


def test_detect_csv():
    r = detect_format(CSV)
    assert r["format"] == "csv"
    assert r["confidence"] >= 0.6


def test_detect_windows_xml():
    r = detect_format(WINDOWS_XML)
    assert r["format"] == "windows"


def test_detect_noise_is_generic_low_confidence():
    noise = ["hello world this is not a log", "random text line two", "more noise here"]
    r = detect_format(noise)
    assert r["format"] == "generic"


def test_detect_empty_input():
    r = detect_format([])
    assert r["format"] == "generic"
    assert r["confidence"] == 0.0
