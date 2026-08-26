"""Deterministic IOC validators — every indicator is structurally verified."""

import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RX = re.compile(
    r"^(?=.{1,253}\.?[a-z]{2,24}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
    re.I,
)

# Extensions that make a dotted token a filename, not a domain
FILE_EXTS = {
    "log", "txt", "cfg", "conf", "xml", "json", "csv", "yaml", "yml", "pid",
    "bak", "tmp", "gz", "zip", "tar", "pdf", "docx", "xlsx", "pptx",
}

HASH_SPECS = {32: "md5", 40: "sha1", 64: "sha256"}

RESERVED_V4 = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}


def validate_ipv4(value: str) -> dict | None:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    if str(ip) in RESERVED_V4:
        return None
    return {
        "value": str(ip),
        "type": "ipv4",
        "confidence": 0.99,
        "private": ip.is_private,
    }


def validate_ipv6(value: str) -> dict | None:
    try:
        ip = ipaddress.IPv6Address(value)
    except ValueError:
        return None
    return {
        "value": str(ip),
        "type": "ipv6",
        "confidence": 0.97,
        "private": ip.is_private,
    }


def validate_domain(value: str) -> dict | None:
    v = value.rstrip(".").lower()
    if "." not in v or len(v) > 253:
        return None
    tld = v.rsplit(".", 1)[-1]
    if tld in FILE_EXTS or tld.isdigit():
        return None
    if not DOMAIN_RX.match(v):
        return None
    labels = v.split(".")
    if any(len(l) > 63 for l in labels):
        return None
    return {"value": v, "type": "domain", "confidence": 0.85}


def validate_url(value: str) -> dict | None:
    if not re.match(r"^https?://", value, re.I):
        return None
    if len(value) > 2048:
        return None
    try:
        p = urlparse(value)
    except ValueError:
        return None
    if not p.netloc:
        return None
    host = p.hostname or ""
    is_ip = bool(validate_ipv4(host) or validate_ipv6(host.strip("[]")))
    if not is_ip and not validate_domain(host):
        return None
    return {
        "value": value[:2000],
        "type": "url",
        "confidence": 0.95,
        "host": host,
    }


def validate_hash(value: str) -> dict | None:
    kind = HASH_SPECS.get(len(value))
    if not kind or not re.fullmatch(r"[0-9a-f]+", value, re.I):
        return None
    return {"value": value.lower(), "type": kind, "confidence": 0.99}
