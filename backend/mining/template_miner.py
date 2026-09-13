"""Unsupervised template mining (M4): offline Drain-style fallback.

When the format detector's confidence is below threshold, lines are grouped
into learned templates by fixed-length token prefix + token-count bucket,
then parameterized by masking tokens that vary across the group. No network,
no model download — a pure, deterministic local algorithm. Provenance is
recorded per event so an analyst can audit exactly how a line was parsed.
"""

import hashlib
import re
from collections import Counter

from core.storage import db

# Below this detection confidence the miner is tried before generic fallback
MIN_CONFIDENCE = 0.30

PREFIX_LEN = 2        # Drain-style fixed prefix tokens (ts/host token positions)
MASK_TOKENS = {
    "<IPV4>", "<DIGIT>", "<HEX>", "<EPOCH>", "<URL>", "<DURATION>", "<EMAIL>",
}
IPV4_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EPOCH_RX = re.compile(r"\b1\d{9}(\.\d+)?\b")
HEX_RX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
URL_RX = re.compile(r"https?://\S+")
DURATION_RX = re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s|sec|seconds|min|minutes)\b", re.I)
EMAIL_RX = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
NUM_RX = re.compile(r"\b\d+\b")
WS_RX = re.compile(r"\s+")


def _mask_variables(line: str) -> str:
    s = URL_RX.sub("<URL>", line)
    s = EMAIL_RX.sub("<EMAIL>", s)
    s = IPV4_RX.sub("<IPV4>", s)
    s = EPOCH_RX.sub("<EPOCH>", s)
    s = DURATION_RX.sub("<DURATION>", s)
    s = HEX_RX.sub("<HEX>", s)
    s = NUM_RX.sub("<DIGIT>", s)
    return s


def _template_key(masked: str) -> tuple:
    tokens = masked.split()
    return (len(tokens), tuple(tokens[:PREFIX_LEN]))


def mine_templates(lines: list[str], min_support: int = 2) -> list[dict]:
    """Group lines into templates. Returns [{template, mask, count, sample}].

    Deterministic: identical input lines always produce identical templates.
    """
    groups: dict[tuple, Counter] = {}
    examples: dict[tuple, str] = {}
    for raw in lines:
        if not raw or not raw.strip():
            continue
        masked = _mask_variables(raw.strip())
        key = _template_key(masked)
        groups.setdefault(key, Counter())[masked] += 1
        examples.setdefault(key, raw.strip())

    templates = []
    for key, variants in groups.items():
        mask, count = variants.most_common(1)[0]
        # normalize runs of whitespace the mask itself introduced
        mask = WS_RX.sub(" ", mask).strip()
        if count >= min_support:
            templates.append({
                "template_key": "len=%d|prefix=%s" % (key[0], " ".join(key[1])),
                "template": mask,
                "count": count,
                "sample": examples[key],
            })
    templates.sort(key=lambda t: (-t["count"], t["template"]))
    return templates


def extract_timestamp_from_template(raw_line: str) -> str:
    """Best-effort timestamp span from an unknown-format line (for the
    learned-template path only; the normalizer's richer parser set is not
    consulted here). Returns '' when nothing timestamp-like is present.

    Scans multi-token spans because common stamps split across whitespace:
    ISO "2026-08-25 10:30:01" (date + time) and RFC3164 "Aug 25 10:30:01".
    """
    from normalization.normalizer import parse_timestamp
    for m in TS_SPAN_RX.finditer(raw_line):
        ts = parse_timestamp(m.group(0).strip(",;:"))
        if ts:
            return ts
    return ""


# Candidate timestamp spans, tried in order: ISO8601 (T- or space-separated),
# RFC3164 syslog stamp ("Aug 25 10:30:01"), bare epoch seconds/millis.
TS_SPAN_RX = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\b1\d{9}(?:\.\d+)?\b|\b1\d{12}\b")


def _timestamp_span(raw_line: str) -> str:
    """Raw timestamp-like span from a line (date+time, syslog, or epoch)."""
    m = TS_SPAN_RX.search(raw_line)
    return m.group(0).strip(",;:") if m else ""


def parse_learned_line(raw: str, templates: list[dict],
                       generic_parser=None) -> dict | None:
    """Parse a line via the learned template set. A line matches when its
    variable-masked shape falls in the same Drain group (token count +
    fixed prefix) as a learned template — the same grouping the miner used —
    so constant tokens that survived masking (module names, hosts) don't
    split one logical template into false strangers. Returns fields tagged
    with parsed_by=learned_template provenance; otherwise defers to the
    generic fallback parser so unknown stragglers are still normalized."""
    if not raw or not raw.strip():
        return None
    masked = WS_RX.sub(" ", _mask_variables(raw.strip())).strip()
    tokens = masked.split()
    key = "len=%d|prefix=%s" % (len(tokens), " ".join(tokens[:PREFIX_LEN]))
    if any(t.get("template_key") == key for t in templates):
        mask_hash = hashlib.sha256(masked.encode()).hexdigest()[:16]
        fields = {
            "event_type": "learned_template_event",
            "message": raw,
            "_learned_mask": mask_hash,
            "_extras": {"parsed_by": "learned_template",
                        "learned_mask": mask_hash},
        }
        span = _timestamp_span(raw)
        if span:
            fields["ts_raw"] = span
        return fields
    return generic_parser(raw) if generic_parser else None


def persist_templates(job_id: str, templates: list[dict]) -> None:
    """Store learned templates for audit + reuse (learned_templates table)."""
    with db() as conn:
        conn.execute("DELETE FROM learned_templates WHERE job_id = ?", (job_id,))
        for t in templates:
            conn.execute(
                "INSERT INTO learned_templates"
                " (job_id, template_key, template, mask_hash, line_count, sample)"
                " VALUES (?,?,?,?,?,?)",
                (job_id, t["template_key"], t["template"],
                 hashlib.sha256(t["template"].encode()).hexdigest()[:16],
                 t["count"], t["sample"][:400]))


def load_templates(job_id: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT template_key, template, line_count, sample"
            " FROM learned_templates WHERE job_id = ?"
            " ORDER BY line_count DESC, template", (job_id,)).fetchall()
    return [dict(r) for r in rows]
