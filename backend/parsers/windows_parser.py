"""Windows Event Log parser: XML <Event> fragments (streamed) + classic .txt blocks."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from parsers.registry import register_file

EVENT_OPEN = re.compile(r"<Event\b")
EVENT_CLOSE = "</Event>"
BLOCK_SEP = re.compile(r"\n\s*\n")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@register_file("windows")
def iter_windows(path):
    path = Path(path)
    buf: list[str] = []
    inside = False
    saw_xml = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if EVENT_OPEN.search(line):
                inside = True
                saw_xml = True
            if inside:
                buf.append(line)
                if EVENT_CLOSE in line:
                    fragment = "".join(buf).strip()
                    buf = []
                    inside = False
                    fields = _parse_event_xml(fragment)
                    if fields is not None:
                        yield 0, fragment[:2000], fields
            elif "Log Name:" in line:
                block_lines = [line]
                for cont in fh:
                    block_lines.append(cont)
                    if BLOCK_SEP.search(cont):
                        break
                block = "".join(block_lines).strip()
                fields = _parse_event_text(block)
                if fields:
                    yield 0, block[:2000], fields
    if not saw_xml:
        return
    if buf:  # trailing unterminated event — parse what we have
        fields = _parse_event_xml("".join(buf))
        if fields is not None:
            yield 0, "".join(buf)[:2000], fields


def _parse_event_xml(fragment: str) -> dict | None:
    try:
        root = ET.fromstring(fragment)
    except ET.ParseError:
        return None
    if _local(root.tag) != "Event":
        return None
    fields: dict = {}
    for child in root.iter():
        tag = _local(child.tag)
        if tag == "EventID" and child.text and child.text.strip().isdigit():
            fields["event_id"] = int(child.text.strip())
        elif tag == "TimeCreated":
            fields["ts_raw"] = child.attrib.get("SystemTime", "")
        elif tag == "Computer" and child.text:
            fields["hostname"] = child.text.strip()
        elif tag == "Level":
            lvl = (child.text or "").strip()
            fields["severity_hint"] = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW", "0": "LOW"}.get(lvl, "LOW")
        elif tag == "Data" and child.text:
            name = child.attrib.get("Name", "data").lower()
            fields[name if name.isidentifier() else "data"] = child.text.strip()
        elif tag == "Provider":
            fields["source"] = child.attrib.get("Name", "")
    # Canonical identity fields for downstream rules/grouping
    for name_key in ("targetusername", "subjectusername", "username"):
        val = fields.get(name_key)
        if val and val not in ("-", "") and not fields.get("username"):
            fields["username"] = val
            break
    ip_val = fields.get("ipaddress")
    if ip_val and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", str(ip_val)):
        fields["src_ip"] = str(ip_val)
    fields.setdefault("event_type", "windows_event")
    fields["message"] = fragment[:500]
    return fields


CLASSIC_FIELDS = {
    "Log Name": "channel",
    "Source": "source",
    "Event ID": "event_id",
    "Level": "severity_hint",
    "Computer": "hostname",
}


def _parse_event_text(block: str) -> dict | None:
    fields: dict = {}
    message_lines: list[str] = []
    for ln in block.splitlines():
        matched = False
        for label, canon in CLASSIC_FIELDS.items():
            if ln.startswith(label + ":"):
                val = ln.split(":", 1)[1].strip()
                if label == "Event ID":
                    val_clean = val.lstrip(">").split()[0] if val else ""
                    if val_clean.isdigit():
                        fields["event_id"] = int(val_clean)
                elif label == "Level":
                    fields["severity_hint"] = {"Critical": "CRITICAL", "Error": "HIGH",
                                               "Warning": "MEDIUM", "Information": "LOW"}.get(val, "LOW")
                else:
                    fields[canon] = val
                matched = True
                break
        if not matched and ln.strip() and ":" not in ln[:20]:
            message_lines.append(ln.strip())
    if not fields:
        return None
    if message_lines:
        fields["message"] = " ".join(message_lines)[:500]
    fields.setdefault("event_type", "windows_event")
    return fields
