"""Parser Lab API (M4): live parsing against the existing parser registry.

Read-only reuse of the EXACT ingestion code path — detector.py confidence
scoring + the registered line parsers (including M4 vendor parsers). Nothing
is written to the DB; the upload/paste flow is untouched.
"""

import time

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from core.rbac import require_role
from parsers.detector import detect_format
from parsers.load_all import *  # noqa: F401,F403 — registers all parsers
from parsers.registry import LINE_PARSERS, get_line_parser

router = APIRouter()

FALLBACK_LABEL = "unknown — generic fallback"


class LabBody(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)


def _refine_label(fmt: str, fields: dict) -> str:
    """Narrow a detected family to the named parser that matched it."""
    if fmt == "firewall" and fields:
        src = str(fields.get("hostname") or "") + " " + str(fields.get("message") or "")
        if "devname=" in src:
            return "fortinet"
        if "product=" in src:
            return "check_point"
        if src.startswith("%"):
            return "cisco_asa"
    if fmt == "json" and fields:
        src = str(fields.get("source") or "")
        if src.startswith("aws-"):
            return "cloudtrail"
        if src == "okta":
            return "okta"
        if src == "crowdstrike-falcon":
            return "crowdstrike"
    return fmt


@router.post("/parserlab/parse")
def parser_lab(body: LabBody, _: dict = Depends(require_role("analyst"))):
    lines = body.text.splitlines()
    sample = [ln for ln in lines if ln.strip()][:300]
    fmt_info = detect_format(sample)

    fmt = fmt_info["format"]
    parser = get_line_parser(fmt)
    generic = get_line_parser("generic")

    t0 = time.perf_counter()
    per_line = []
    named = fallback = 0
    type_counts: dict[str, int] = {}
    for i, raw in enumerate(lines, start=1):
        if not raw.strip():
            per_line.append({"line_no": i, "raw": raw, "parser": "blank",
                             "fields": None})
            continue
        label = FALLBACK_LABEL
        # EXACT ingestion behavior: detected-format parser first
        fields = parser(raw) if parser else None
        if fields is not None and fmt != "generic":
            label = _refine_label(fmt, fields)
            named += 1
        else:
            # parser rejected (or none): try remaining registered named
            # parsers deterministically, then the generic fallback
            for reg_fmt in sorted(LINE_PARSERS):
                if reg_fmt in (fmt, "generic"):
                    continue
                alt = LINE_PARSERS[reg_fmt](raw)
                if alt is not None:
                    fields = alt
                    label = (_refine_label("firewall", alt)
                             if reg_fmt == "firewall" else reg_fmt)
                    named += 1
                    break
            else:
                fields = generic(raw) if generic else None
                label = FALLBACK_LABEL
                fallback += 1
        per_line.append({
            "line_no": i,
            "raw": raw[:800],
            "parser": label if fields else "unparsed",
            "fields": {k: v for k, v in (fields or {}).items()
                       if not str(k).startswith("_")} if fields else None,
        })
        if fields:
            et = fields.get("event_type") or "unclassified"
            type_counts[et] = type_counts.get(et, 0) + 1
    elapsed = max(time.perf_counter() - t0, 1e-9)

    total = sum(1 for ln in per_line if ln["parser"] != "blank")
    distinct = len({ln["parser"] for ln in per_line
                    if ln["parser"] not in ("blank", FALLBACK_LABEL, "unparsed")})
    return {
        "detected_format": fmt_info["format"],
        "subtype": fmt_info.get("subtype"),
        "confidence": fmt_info["confidence"],
        "scores": fmt_info.get("scores", {}),
        "summary": {
            "records": total,
            "named_parser_pct": round((named / total) * 100, 1) if total else 0.0,
            "fallback_pct": round((fallback / total) * 100, 1) if total else 0.0,
            "distinct_formats": distinct,
            "lines_per_second": int(total / elapsed) if elapsed > 0 else 0,
        },
        "event_types": dict(sorted(type_counts.items(), key=lambda kv: -kv[1])[:15]),
        "lines": per_line[:2000],
    }
