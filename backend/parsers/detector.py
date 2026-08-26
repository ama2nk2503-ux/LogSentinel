"""Heuristic format detection with actual calculated confidence scores."""

import json
import re
from collections import Counter

SAMPLE_SIZE = 300

SIGNATURES = {
    "syslog": re.compile(
        r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w\-.]+(\[\d+\])?:"
    ),
    "syslog_rfc5424": re.compile(r"^<\d{1,3}>\d*\s"),
    "apache": re.compile(
        r'^\S+\s+\S+\s+\S+\s+\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'
        r'\s+"[^"]*"\s+\d{3}\s+(\d+|-)'
    ),
    "windows_xml": re.compile(r"<Event\s+xmlns|<Event>"),
    "windows_text": re.compile(r"^(Log Name|Source|Event ID):\s", re.M),
    "suricata": re.compile(r"\[\*\*\]\s+\[\d+:\d+:\d+\]"),
    "squid": re.compile(r"^\d{9,12}\.\d{3}\s+\d+\s+[\d.]+\s+(TCP_|UDP_|NONE_)"),
}

KV_PAIR = re.compile(r"\b([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|[^\s]+)")
NET_KV_KEYS = {"src", "dst", "src_ip", "dst_ip", "source", "destination", "sport",
               "dport", "src_port", "dst_port", "proto", "protocol", "action",
               "SRC", "DST", "SPORT", "DPORT", "PROTO", "ACTION"}
ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")

SUBTYPES = [
    ("sshd", "Linux SSH / Syslog"),
    ("sudo", "Linux Privilege Escalation / Syslog"),
    ("su[", "Linux Auth / Syslog"),
    ("CRON", "Cron / Syslog"),
    ("named", "DNS (Syslog)"),
    ("dnsmasq", "DNS/DHCP (Syslog)"),
    ("dhcpd", "DHCP (Syslog)"),
    ("kernel|ufw|iptables", "Firewall (Syslog)"),
]


def _is_json(line: str) -> bool:
    s = line.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return False
    try:
        json.loads(s)
        return True
    except (ValueError, RecursionError):
        return False


def _csv_score(lines) -> tuple[float, int]:
    """Return (share_of_consistent_rows, column_count)."""
    counts = Counter()
    for ln in lines:
        if ln.strip():
            counts[ln.count(",")] += 1
    if not counts:
        return 0.0, 0
    cols, freq = counts.most_common(1)[0]
    if cols < 2:
        return 0.0, cols
    return freq / sum(counts.values()), cols + 1


def detect_format(lines: list[str]) -> dict:
    sample = [ln for ln in lines if ln.strip()][:SAMPLE_SIZE]
    total = len(sample)
    result = {"format": "generic", "subtype": None, "confidence": 0.0, "scores": {}}
    if total == 0:
        return result

    joined_sample = "\n".join(sample)

    # --- block-structured formats: judged by structural markers, not line share ---
    event_tags = len(re.findall(r"<Event\b", joined_sample))
    logname_headers = len(re.findall(r"^Log Name:\s", joined_sample, re.M))
    if event_tags or logname_headers:
        fmt = "windows" if (event_tags or logname_headers) else "xml"
        confidence = min(0.99, max(0.80, ((event_tags + logname_headers) / total) * 3))
        result.update(format=fmt, subtype="Windows Event Log",
                      confidence=round(confidence, 3))
        result["scores"] = {"windows": result["confidence"]}
        return result
    stripped = joined_sample.lstrip()
    if stripped.startswith("<?xml") or (
        stripped.startswith("<")
        and sample[0].lstrip().startswith("<")
        and sample[-1].rstrip().endswith(">")
        and "</" in joined_sample
    ):
        result.update(format="xml", subtype="XML Document", confidence=0.85)
        result["scores"] = {"xml": 0.85}
        return result

    scores: Counter = Counter()
    for ln in sample:
        for name, rx in SIGNATURES.items():
            if rx.search(ln):
                scores[name.replace("_rfc5424", "").replace("_text", "")] += 1
                break  # first matching family wins per line
        else:
            pairs = KV_PAIR.findall(ln)
            net_pairs = sum(1 for k, _ in pairs if k in NET_KV_KEYS)
            if net_pairs >= 2:
                scores["firewall"] += 1
            elif ISO_TS.match(ln) and pairs:
                scores["firewall"] += 0.5
            elif _is_json(ln):
                scores["json"] += 1

    # whole-line JSON check (strong signal)
    json_hits = sum(1 for ln in sample if _is_json(ln))
    if json_hits / total >= 0.6:
        scores["json"] = max(scores["json"], json_hits)

    # CSV structural check
    csv_share, csv_cols = _csv_score(sample)
    if csv_share >= 0.8:
        scores["csv"] = csv_share * total * 0.95

    shares = {k: v / total for k, v in scores.items()}
    result["scores"] = {k: round(v, 3) for k, v in sorted(shares.items(), key=lambda x: -x[1])}
    if not scores:
        result["confidence"] = round(1.0 - min(1.0, _noise_ratio(sample)), 2)
        return result

    fmt, share = max(shares.items(), key=lambda kv: kv[1])
    result["format"] = fmt
    result["confidence"] = round(min(0.99, share), 3)

    if fmt == "syslog":
        joined = "\n".join(sample)
        for pattern, label in SUBTYPES:
            if re.search(pattern, joined):
                result["subtype"] = label
                break
    elif fmt == "apache":
        joined = "\n".join(sample[:40])
        result["subtype"] = "Nginx Combined" if "nginx" in joined.lower() else "Apache Combined"

    if result["confidence"] < 0.3:
        result["format"] = "generic"
        result["subtype"] = None
    return result


def _noise_ratio(sample) -> float:
    """Fraction of lines with no recognizable timestamp/IP structure."""
    weak = 0
    for ln in sample:
        if not (ISO_TS.search(ln) or re.search(r"\d{1,3}(\.\d{1,3}){3}", ln)):
            weak += 1
    return weak / len(sample) if sample else 1.0
