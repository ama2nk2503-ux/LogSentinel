"""Structured formats: JSON (jsonl / array / object), CSV, XML — file-level streaming."""

import csv
import json
import xml.etree.ElementTree as ET  # stdlib; external entities not resolved
from pathlib import Path

from parsers.registry import register_file

WHOLE_JSON_LIMIT = 50 * 1024 * 1024


def _flatten(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


@register_file("json")
def iter_json(path):
    path = Path(path)
    first = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        while True:
            ch = fh.read(1)
            if not ch:
                break
            if not ch.isspace():
                first = ch
                break
    if first == "[" or (first == "{" and path.stat().st_size <= WHOLE_JSON_LIMIT):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            records = data if isinstance(data, list) else [data]
            for i, rec in enumerate(records):
                if isinstance(rec, dict):
                    yield i + 1, json.dumps(rec), _flatten(rec)
            return
        except (ValueError, RecursionError):
            pass  # fall through to jsonl
    line_no = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line_no += 1
            s = raw.strip()
            if not s.endswith("}") and not s.endswith("]"):
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield line_no, raw.rstrip("\r\n"), _flatten(rec)


@register_file("csv")
def iter_csv(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        line_no = 1
        for row in reader:
            line_no += 1
            clean = {k: v for k, v in row.items() if k and v not in (None, "")}
            yield line_no, ",".join(str(v) for v in clean.values()), clean


@register_file("xml")
def iter_xml(path):
    try:
        for event, elem in ET.iterparse(path, events=("end",)):
            yield from _xml_record(elem)
            elem.clear()
    except ET.ParseError as e:
        raise ValueError(f"Malformed XML: {e}") from e


def _xml_record(elem):
    tag = elem.tag.rsplit("}", 1)[-1].lower()
    if tag in ("root", "events", "logs", "records"):
        return
    fields = {}
    fields.update({f"@{k}": v for k, v in elem.attrib.items()})
    text = (elem.text or "").strip()
    if text:
        fields[elem.tag] = text
    for child in elem:
        ctag = child.tag.rsplit("}", 1)[-1]
        ctext = (child.text or "").strip()
        fields[ctag] = ctext if ctext else _attrs(child)
    if len(fields) > 1:
        yield 0, f"<{elem.tag}>...</{elem.tag}>", fields


def _attrs(elem) -> dict:
    out = {f"@{k}": v for k, v in elem.attrib.items()}
    t = (elem.text or "").strip()
    if t:
        out["value"] = t
    for sub in elem:
        out[sub.tag] = (sub.text or "").strip()
    return out or ""
