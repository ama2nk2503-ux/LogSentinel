"""Branded multi-page PDF threat report via reportlab."""

import io
import json

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from core.storage import db
from intelligence.aggregator import build_intel


BRAND_DARK = colors.HexColor("#0d1320")
ACCENT = colors.HexColor("#10b981")
WARN = colors.HexColor("#f97316")
CRIT = colors.HexColor("#ef4444")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Brand", fontName="Helvetica-Bold", fontSize=20,
                          textColor=ACCENT, spaceAfter=2))
    ss.add(ParagraphStyle("Sub", fontName="Helvetica", fontSize=9,
                          textColor=colors.HexColor("#64748b")))
    ss.add(ParagraphStyle("H", fontName="Helvetica-Bold", fontSize=13,
                          textColor=BRAND_DARK, spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle("Body", fontSize=9.5, leading=13))
    return ss


def generate_pdf(job_id: str) -> bytes:
    with db() as conn:
        job = conn.execute("SELECT filename FROM jobs WHERE id=?", (job_id,)).fetchone()
        if job is None:
            raise ValueError("Job not found")

    intel = build_intel(job_id)
    reports = intel["reports"]
    indicators = sorted(intel["indicators"],
                        key=lambda i: -i["related_events"])[:15]
    cards = _cards(job_id)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm,
                            bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm)
    ss = _styles()
    story = [
        Paragraph("LOGSENTINEL", ss["Brand"]),
        Paragraph("Universal Cybersecurity Data Preparation & Threat Intelligence Layer", ss["Sub"]),
        Spacer(1, 6),
        Paragraph(f"<b>Threat Intelligence Report</b><br/>Dataset: {job['filename']}",
                  ss["H"]),
    ]

    # ---- executive summary ----
    story.append(Paragraph("1. Executive Summary", ss["H"]))
    summary_rows = [["Metric", "Value"]] + [[k.replace("_", " ").title(), str(v)]
                                            for k, v in cards.items()]
    t = Table(summary_rows, colWidths=[70 * mm, 40 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]))
    story += [t, Spacer(1, 10)]

    story.append(Paragraph("Severity Distribution", ss["Body"]))
    story.append(_severity_chart(cards.get("severity_by_level") or {}))
    story.append(PageBreak())

    # ---- findings ----
    story.append(Paragraph("2. Threat Findings", ss["H"]))
    if not reports:
        story.append(Paragraph("No correlated threat incidents were identified "
                               "in this dataset.", ss["Body"]))
    for idx, r in enumerate(reports, start=1):
        color = CRIT if r["classification"] == "MALICIOUS" else WARN
        head = Table([[f"{idx}. {r['title']}",
                       f"risk {r['risk_score']} · {r['severity']} · {r['classification']}"]],
                     colWidths=[110 * mm, 64 * mm])
        head.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), color),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story += [head, Spacer(1, 3)]
        story.append(Paragraph(
            f"<b>Source:</b> {r['source']} &nbsp;&nbsp; <b>Events:</b> {r['events']}"
            f" &nbsp;&nbsp; <b>Confidence:</b> {r['confidence']:.2f}", ss["Body"]))
        for why in r["why"]:
            story.append(Paragraph(f"• {why}", ss["Body"]))
        ev_lines = "<br/>".join(
            f"[{(e.get('ts') or '')[:19]}] {e.get('rule','')}: {e.get('excerpt','')[:90]}"
            for e in r["evidence"][:5])
        if ev_lines:
            story.append(Spacer(1, 2))
            story.append(Paragraph(f"<b>Evidence:</b><br/>{ev_lines}", ss["Body"]))
        story.append(Paragraph(f"<b>Recommended response:</b> {r['recommended_response']}",
                               ss["Body"]))
        story.append(Spacer(1, 8))

    if any(r for r in reports):
        pass
    story.append(PageBreak())

    # ---- indicators ----
    story.append(Paragraph("3. Threat Indicators", ss["H"]))
    if indicators:
        rows = [["Indicator", "Type", "Threat", "Sev", "Conf", "Events"]]
        rows += [[i["value"][:40], i["type"], i["threat_type"][:22],
                  i["severity"], f"{i['confidence']:.2f}", str(i["related_events"])]
                 for i in indicators]
        t2 = Table(rows, repeatRows=1)
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No indicators extracted.", ss["Body"]))

    doc.build(story)
    data = buf.getvalue()
    _validate(data)
    return data


def _cards(job_id: str) -> dict:
    from api.routes_dashboard import dashboard
    try:
        d = dashboard(job_id)
        cards = dict(d["cards"])
        sev = {c["label"]: c["count"] for c in d["charts"]["severity"]}
        cards["severity_by_level"] = sev
        return cards
    except Exception:
        return {}


def _severity_chart(sev: dict) -> Drawing:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    values = [int(sev.get(k, 0)) for k in order]
    d = Drawing(400, 130)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 40, 20, 300, 95
    bc.data = [values]
    bc.categoryAxis.categoryNames = order
    bc.valueAxis.valueMin = 0
    bc.bars[0].fillColor = ACCENT
    bc.strokeColor = colors.HexColor("#94a3b8")
    d.add(bc)
    d.add(String(40, 122, "events per severity level",
                 fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#64748b")))
    return d


def _validate(data: bytes) -> None:
    if not data.startswith(b"%PDF"):
        raise ValueError("generated file is not a valid PDF")
    if b"%%EOF" not in data[-1024:]:
        raise ValueError("PDF missing EOF marker — possibly truncated")
    if len(data) < 2000:
        raise ValueError("suspiciously small PDF — refusing to serve")
