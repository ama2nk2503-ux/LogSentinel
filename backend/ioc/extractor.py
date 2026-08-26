"""IOC extraction: regex candidates -> deterministic validation -> dedup.

Also flags suspicious activity patterns (encoded PowerShell, download
commands, injection payloads). Purely rule-based; no AI in the loop.
"""

import re

from ioc.validator import validate_domain, validate_hash, validate_ipv4, validate_ipv6, validate_url

IPV4_RX = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RX = re.compile(r"(?<![:\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:\w])")
# '/' in lookbehind: tokens inside URL/path segments (/products.php) are not domains;
# '='/'/'/'(' in lookahead: JS property access (document.location=...) is not a domain.
DOMAIN_RX = re.compile(
    r"(?<![\w@./\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w.\-='(])",
    re.I,
)
URL_RX = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
HASH_RX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")
SCRIPT_BLOCK = re.compile(r"<script\b.*?</script>", re.I | re.S)

# Version-number suppression: v1.2.3.4 / version 1.2.3.4
VERSION_CTX = re.compile(r'(?:\bv|version)\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.I)

SUSPICIOUS_PATTERNS = [
    ("encoded_powershell", re.compile(r"-enc(?:odedcommand)?\b", re.I)),
    ("powershell_iex", re.compile(r"\biex\b|\binvoke-expression\b", re.I)),
    ("download_command", re.compile(
        r"downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|"
        r"certutil\s+-urlcache|bitsadmin\s+/transfer|wget\s+https?://|curl\s+https?://", re.I)),
    ("shell_execution", re.compile(r"/bin/(ba)?sh\s+-c|cmd\.exe\s+/c|powershell\s+-", re.I)),
    ("path_traversal", re.compile(r"(?:\.\./){2,}|/etc/(passwd|shadow)|%2e%2e%2f", re.I)),
    ("sql_injection", re.compile(
        r"union\s+select\b|'\s*or\s+'?1'?='?1|--\s*$|;\s*drop\s+table\b|sleep\(\d+\)", re.I)),
    ("xss_pattern", re.compile(r"<script\b[^>]*>|javascript:|onerror\s*=", re.I)),
    ("command_injection", re.compile(r";\s*(?:cat|id|whoami|nc|bash)\b|\|\s*(?:cat|id|whoami|nc)\b", re.I)),
]


def extract_iocs(text: str) -> list[dict]:
    """Return deduplicated validated IOCs found in free text."""
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    def add(candidate):
        if candidate and (candidate["value"], candidate["type"]) not in seen:
            seen.add((candidate["value"], candidate["type"]))
            out.append(candidate)

    for m in URL_RX.finditer(text):
        url = validate_url(m.group(0))
        if url:
            add(url)
            host = url.get("host", "")
            ip = validate_ipv4(host)
            if ip is None:
                ip = validate_ipv6(host.strip("[]"))
            if ip is not None:
                add(ip)
            elif validate_domain(host):
                add(validate_domain(host))

    version_spans = [m.span(1) for m in VERSION_CTX.finditer(text)]
    for m in IPV4_RX.finditer(text):
        if any(s <= m.start() < e for s, e in version_spans):
            continue
        add(validate_ipv4(m.group(0)))

    for m in IPV6_RX.finditer(text):
        token = m.group(0)
        if ":" not in token or token.count(":") < 2:
            continue
        add(validate_ipv6(token))

    # Domain mining uses script-stripped text to avoid JS-artifact tokens
    domain_text = SCRIPT_BLOCK.sub(" ", text)
    for m in DOMAIN_RX.finditer(domain_text):
        add(validate_domain(m.group(1)))

    for m in HASH_RX.finditer(text):
        add(validate_hash(m.group(0)))

    return out


def detect_suspicious(text: str) -> list[str]:
    if not text:
        return []
    return [name for name, rx in SUSPICIOUS_PATTERNS if rx.search(text)]
