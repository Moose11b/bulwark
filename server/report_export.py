"""
Client-ready report rendering: DOCX and PDF.

Takes the enriched report context (the engagement's ROE, execution log, and
findings — with CVSS/severity) and produces a branded, structured document:
cover page, executive summary with a findings-by-severity table, findings
detail (description / impact / reproduction / remediation / evidence), and the
execution log. DOCX is the editable consultant deliverable; PDF is the
read-only counterpart.

Pure formatting of data already entered — nothing here runs or contacts a target.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   "informational": 4, None: 5}
# Cartographic palette — matches the app UI (survey terracotta / teal, map ink).
_ACCENT = "B0472C"     # survey terracotta
_TEAL = "3E6B72"       # survey teal
_INK = "20261E"        # topographic ink
_SEVERITY_COLOR = {
    "critical": "9C2B1B", "high": "C0562E", "medium": "B08814",
    "low": "3E7A5A", "informational": "3E6B72",
}
_SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "informational": "Informational"}

# ATT&CK tactic colours — mirror the app UI.
_TACTIC_COLOR = {
    "reconnaissance": "6B7F8C", "resource-development": "6B5B41",
    "initial-access": "9C3B2E", "execution": "A9822C", "persistence": "7A6A9C",
    "privilege-escalation": "B06A2E", "defense-evasion": "7C6A55",
    "credential-access": "4E7C6B", "discovery": "3C5A6B",
    "lateral-movement": "8A6D3B", "collection": "5E6B2C",
    "command-and-control": "6B5B41", "exfiltration": "97362A", "impact": "5A3A3A",
}
_WORKED = {"succeeded", "fell_back"}
_FAILED = {"failed", "blocked"}


def _roadmap_drawing(ctx: dict, avail_width: float):
    """A vector attack-path roadmap (nodes + arrows) for the PDF, or None."""
    from reportlab.graphics.shapes import Circle, Drawing, Group, Line, Polygon, String
    from reportlab.lib import colors

    steps = ctx.get("steps", [])
    if not steps:
        return None

    r = 13.0
    gap = 86.0
    row_h = 58.0
    mx = 6.0
    per_row = max(1, int((avail_width - 2 * mx) // gap))
    rows = (len(steps) + per_row - 1) // per_row
    top_y = rows * row_h - 18
    height = rows * row_h + 6
    d = Drawing(avail_width, height)
    accent = colors.HexColor("#B0472C")
    crit = colors.HexColor("#9C2B1B")
    faint = colors.HexColor("#828A7B")
    line_c = colors.HexColor("#B4A788")

    def node_xy(i):
        row, col = divmod(i, per_row)
        return mx + r + col * gap, top_y - row * row_h

    def arrow(x1, y1, x2, y2, worked):
        col = accent if worked else faint
        ln = Line(x1, y1, x2, y2, strokeColor=col, strokeWidth=2 if worked else 1.2)
        if not worked:
            ln.strokeDashArray = [3, 4]
        d.add(ln)
        # arrowhead
        import math
        ang = math.atan2(y2 - y1, x2 - x1)
        ah = 5.0
        p = Polygon(points=[
            x2, y2,
            x2 - ah * math.cos(ang - 0.5), y2 - ah * math.sin(ang - 0.5),
            x2 - ah * math.cos(ang + 0.5), y2 - ah * math.sin(ang + 0.5),
        ], fillColor=col, strokeColor=col)
        d.add(p)

    for i, s in enumerate(steps):
        cx, cy = node_xy(i)
        oc = s.get("outcome") or "not_started"
        tcol = colors.HexColor("#" + _TACTIC_COLOR.get(s.get("tactic"), "8A6D3B"))
        worked = oc in _WORKED
        if i < len(steps) - 1:
            nx, ny = node_xy(i + 1)
            if (i % per_row) != per_row - 1:  # same row → straight
                arrow(cx + r, cy, nx - r - 4, ny, worked)
            else:  # row wrap → drop then across
                arrow(cx, cy - r, nx, ny + r + 4, worked)
        # node
        if worked:
            fill, txt = tcol, colors.HexColor("#F6EFE6")
            stroke = tcol
        elif oc in _FAILED:
            fill, txt, stroke = colors.white, crit, crit
        else:
            fill, txt, stroke = colors.white, colors.HexColor("#20261E"), line_c
        circ = Circle(cx, cy, r, fillColor=fill, strokeColor=stroke, strokeWidth=2)
        if oc in ("skipped", "not_started"):
            circ.strokeDashArray = [3, 3]
        d.add(circ)
        d.add(String(cx, cy - 4, str(i + 1), fontName="Helvetica-Bold",
                     fontSize=10, fillColor=txt, textAnchor="middle"))
        d.add(String(cx, cy - r - 11, s.get("technique_id") or "",
                     fontName="Courier", fontSize=7, fillColor=faint, textAnchor="middle"))
    return d


def _hex(h):
    h = h.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _roadmap_png(ctx: dict):
    """Render the roadmap to PNG bytes (Pillow) for DOCX embedding; None if
    Pillow or a usable font isn't available."""
    steps = ctx.get("steps", [])
    if not steps:
        return None
    try:
        import io as _io
        import math
        from PIL import Image, ImageDraw, ImageFont

        def _font(bold, size):
            for name in (("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),
                         "DejaVuSansMono.ttf"):
                try:
                    return ImageFont.truetype(name, size)
                except Exception:
                    continue
            return ImageFont.load_default()

        ss = 2  # supersample for anti-aliasing
        r, gap, row_h, mx = 15 * ss, 96 * ss, 62 * ss, 12 * ss
        avail = 980 * ss
        per_row = max(1, int((avail - 2 * mx) // gap))
        rows = (len(steps) + per_row - 1) // per_row
        cols = min(len(steps), per_row)
        W = int(mx * 2 + (cols - 1) * gap + r * 2 + 8 * ss)
        H = int(rows * row_h + 10 * ss)
        img = Image.new("RGB", (W, H), (255, 255, 255))
        dr = ImageDraw.Draw(img)
        f_num, f_tid = _font(True, 15 * ss), _font(False, 9 * ss)
        accent, crit, faint, line_c, ink = (
            _hex("#B0472C"), _hex("#9C2B1B"), _hex("#828A7B"),
            _hex("#B4A788"), _hex("#20261E"))

        def xy(i):
            row, col = divmod(i, per_row)
            return mx + r + col * gap, int(row * row_h + r + 6 * ss)

        def arrow(x1, y1, x2, y2, worked):
            col = accent if worked else faint
            w = 3 if worked else 2
            if worked:
                dr.line([(x1, y1), (x2, y2)], fill=col, width=w)
            else:
                # dashed
                n = max(1, int(math.hypot(x2 - x1, y2 - y1) // (7 * ss)))
                for k in range(n):
                    if k % 2:
                        continue
                    a, b = k / n, min(1, (k + 1) / n)
                    dr.line([(x1 + (x2 - x1) * a, y1 + (y2 - y1) * a),
                             (x1 + (x2 - x1) * b, y1 + (y2 - y1) * b)], fill=col, width=w)
            ang = math.atan2(y2 - y1, x2 - x1)
            ah = 7 * ss
            dr.polygon([(x2, y2),
                        (x2 - ah * math.cos(ang - 0.5), y2 - ah * math.sin(ang - 0.5)),
                        (x2 - ah * math.cos(ang + 0.5), y2 - ah * math.sin(ang + 0.5))],
                       fill=col)

        def ctext(x, y, s, font, fill):
            bb = dr.textbbox((0, 0), s, font=font)
            dr.text((x - (bb[2] - bb[0]) / 2, y - (bb[3] - bb[1]) / 2), s, font=font, fill=fill)

        for i, s in enumerate(steps):
            cx, cy = xy(i)
            oc = s.get("outcome") or "not_started"
            tcol = _hex("#" + _TACTIC_COLOR.get(s.get("tactic"), "8A6D3B"))
            worked = oc in _WORKED
            if i < len(steps) - 1:
                nx, ny = xy(i + 1)
                if (i % per_row) != per_row - 1:
                    arrow(cx + r, cy, nx - r - 4 * ss, ny, worked)
                else:
                    arrow(cx, cy + r, nx, ny - r - 4 * ss, worked)
            if worked:
                fill, txt, stroke = tcol, (246, 239, 230), tcol
            elif oc in _FAILED:
                fill, txt, stroke = (255, 255, 255), crit, crit
            else:
                fill, txt, stroke = (255, 255, 255), ink, line_c
            dr.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill, outline=stroke, width=2 * ss)
            ctext(cx, cy, str(i + 1), f_num, txt)
            ctext(cx, cy + r + 9 * ss, s.get("technique_id") or "", f_tid, faint)

        img = img.resize((W // ss, H // ss), Image.LANCZOS)
        buf = _io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 5),
                                           str(f.get("title") or "")))


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "informational")}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _lbl(v) -> str:
    return str(v).replace("_", " ").replace("-", " ").title() if v else "—"


def _logo_bytes(branding: dict):
    uri = (branding or {}).get("logo_data_uri")
    if not uri:
        return None
    import base64
    import re
    m = re.match(r"data:[^;]+;base64,(.*)", uri, re.S)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1))
    except Exception:
        return None


def _accent_hex(branding: dict) -> str:
    acc = (branding or {}).get("accent")
    if isinstance(acc, str) and len(acc.lstrip("#")) == 6:
        return acc.lstrip("#")
    return _ACCENT


# ── DOCX ──────────────────────────────────────────────────────────

def to_docx(ctx: dict) -> bytes:
    from docx import Document
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    eng = ctx["engagement"]
    roe = ctx.get("roe", {})
    cov = ctx.get("coverage", {})
    findings = _sorted_findings(ctx.get("findings", []))
    counts = _severity_counts(findings)
    branding = ctx.get("branding") or {}
    org_name = branding.get("company_name") or ctx.get("org_name") or "—"
    accent = _accent_hex(branding)
    conf = branding.get("confidentiality") or "CONFIDENTIAL"

    doc = Document()

    def _h1(text: str):
        h = doc.add_heading(level=1)
        r = h.add_run(text)
        r.font.color.rgb = RGBColor.from_string(accent)
        return h

    # Cover — optional org logo.
    logo = _logo_bytes(branding)
    if logo:
        from docx.shared import Inches
        try:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.add_run().add_picture(io.BytesIO(logo), width=Inches(1.7))
        except Exception:
            pass
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(eng.get("name") or "Engagement Report")
    run.bold = True
    run.font.size = Pt(26)
    run.font.color.rgb = RGBColor.from_string(accent)
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run("Penetration Test Report").font.size = Pt(14)
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta.add_run(
        f"Client: {eng.get('client') or '—'}    ·    Prepared by: {org_name}\n"
        f"Generated {_now_str()}"
    ).font.size = Pt(10)
    note = doc.add_paragraph()
    note.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = note.add_run(f"{conf} — Authorized assessment record. Planning and documentation only.")
    r.italic = True
    r.font.size = Pt(9)
    doc.add_page_break()

    # Overview.
    _h1("Overview")
    for k, v in (("Client", eng.get("client")), ("Authorization", eng.get("authorization_ref")),
                 ("Objective", _lbl(eng.get("objective"))), ("Box type", _lbl(eng.get("box_type"))),
                 ("Status", _lbl(eng.get("status")))):
        p = doc.add_paragraph()
        p.add_run(f"{k}: ").bold = True
        p.add_run(str(v) if v else "—")

    # Rules of engagement.
    _h1("Rules of engagement")
    for k, v in (("In-scope platforms", roe.get("scope_platforms")),
                 ("In-scope targets", roe.get("in_scope_targets")),
                 ("Restrictions", roe.get("restrictions")),
                 ("Time budget (h)", roe.get("time_budget_hours"))):
        p = doc.add_paragraph()
        p.add_run(f"{k}: ").bold = True
        p.add_run(", ".join(map(str, v)) if isinstance(v, list) else (str(v) if v else "—"))

    # Executive summary.
    _h1("Executive summary")
    doc.add_paragraph(
        f"Execution coverage: {cov.get('coverage_pct', 0)}% "
        f"({cov.get('steps_worked', 0)} of {cov.get('total_steps', 0)} planned steps worked). "
        f"{len(findings)} finding(s) recorded."
    )
    tbl = doc.add_table(rows=1, cols=2)
    tbl.style = "Light Grid Accent 1"
    hdr = tbl.rows[0].cells
    hdr[0].paragraphs[0].add_run("Severity").bold = True
    hdr[1].paragraphs[0].add_run("Count").bold = True
    for sev in ("critical", "high", "medium", "low", "informational"):
        row = tbl.add_row().cells
        run = row[0].paragraphs[0].add_run(_SEV_LABEL[sev])
        run.font.color.rgb = RGBColor.from_string(_SEVERITY_COLOR[sev])
        run.bold = True
        row[1].paragraphs[0].add_run(str(counts[sev]))

    # Attack-path roadmap (rendered image, if the vector renderer is available).
    png = _roadmap_png(ctx)
    if png:
        from docx.shared import Inches
        _h1("Attack path")
        cap = doc.add_paragraph(
            "Nodes are plan steps (filled = worked, hollow/red = failed, dashed = "
            "skipped); the solid line is the path to the objective.")
        cap.runs[0].italic = True
        cap.runs[0].font.size = Pt(9)
        doc.add_picture(io.BytesIO(png), width=Inches(6.5))

    # Findings detail.
    _h1("Findings")
    if not findings:
        doc.add_paragraph("No findings recorded.")
    for i, f in enumerate(findings, 1):
        h = doc.add_heading(level=2)
        sev = f.get("severity")
        tag = f"[{_SEV_LABEL.get(sev, '—')}] " if sev else ""
        run = h.add_run(f"{i}. {tag}{f.get('title') or 'Untitled'}")
        if sev in _SEVERITY_COLOR:
            run.font.color.rgb = RGBColor.from_string(_SEVERITY_COLOR[sev])
        cvss = f.get("cvss_score")
        if cvss is not None:
            p = doc.add_paragraph()
            p.add_run("CVSS: ").bold = True
            p.add_run(f"{cvss}" + (f"  ({f.get('cvss_vector')})" if f.get("cvss_vector") else ""))
        for label, key in (("Status", "status"), ("Affected assets", "affected_assets"),
                           ("Description", "description"), ("Impact", "impact"),
                           ("Reproduction", "reproduction"), ("Remediation", "remediation"),
                           ("ATT&CK techniques", "technique_ids"), ("References", "references")):
            val = f.get(key)
            if not val:
                continue
            p = doc.add_paragraph()
            p.add_run(f"{label}: ").bold = True
            p.add_run(", ".join(map(str, val)) if isinstance(val, list) else str(val))
        ev = f.get("evidence") or []
        if ev:
            p = doc.add_paragraph()
            p.add_run("Evidence: ").bold = True
            p.add_run("; ".join(
                f"{e.get('filename','?')} (sha256 {str(e.get('sha256',''))[:12]}…)" for e in ev))

    # Execution log.
    _h1("Execution log")
    steps = ctx.get("steps", [])
    if not steps:
        doc.add_paragraph("No steps documented.")
    for s in steps:
        h = doc.add_heading(level=3)
        h.add_run(f"{s.get('index', 0) + 1}. {s.get('name') or s.get('technique_id')} — {_lbl(s.get('outcome'))}")
        meta_bits = [s.get("technique_id"), _lbl(s.get("tactic"))]
        if s.get("operator"):
            meta_bits.append(f"operator {s['operator']}")
        doc.add_paragraph(" · ".join(b for b in meta_bits if b)).italic = True
        if s.get("notes"):
            doc.add_paragraph(s["notes"])

    if branding.get("footer"):
        f = doc.add_paragraph()
        f.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fr = f.add_run(branding["footer"])
        fr.italic = True
        fr.font.size = Pt(8)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ── PDF ────────────────────────────────────────────────────────────

def to_pdf(ctx: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
    from xml.sax.saxutils import escape

    eng = ctx["engagement"]
    roe = ctx.get("roe", {})
    cov = ctx.get("coverage", {})
    findings = _sorted_findings(ctx.get("findings", []))
    counts = _severity_counts(findings)
    branding = ctx.get("branding") or {}
    org_name = branding.get("company_name") or ctx.get("org_name") or "—"
    accent = "#" + _accent_hex(branding)
    conf = branding.get("confidentiality") or "CONFIDENTIAL"

    styles = getSampleStyleSheet()
    h1, h2, body = styles["Heading1"], styles["Heading2"], styles["BodyText"]
    center = ParagraphStyle("center", parent=body, alignment=TA_CENTER)
    cover_title = ParagraphStyle("cover", parent=styles["Title"], fontSize=26, spaceAfter=12,
                                textColor=colors.HexColor(accent))
    h1.textColor = colors.HexColor(accent)

    def esc(v) -> str:
        return escape(str(v)) if v is not None else "—"

    story: list = []
    logo = _logo_bytes(branding)
    if logo:
        try:
            img = Image(io.BytesIO(logo))
            ratio = (img.imageHeight / img.imageWidth) if img.imageWidth else 1
            img.drawWidth = 1.8 * inch
            img.drawHeight = 1.8 * inch * ratio
            img.hAlign = "CENTER"
            story.append(Spacer(1, 1.0 * inch))
            story.append(img)
            story.append(Spacer(1, 0.35 * inch))
        except Exception:
            story.append(Spacer(1, 1.6 * inch))
    else:
        story.append(Spacer(1, 1.6 * inch))
    story.append(Paragraph(esc(eng.get("name") or "Engagement Report"), cover_title))
    story.append(Paragraph("Penetration Test Report", center))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        f"Client: {esc(eng.get('client'))} &nbsp;·&nbsp; Prepared by: {esc(org_name)}", center))
    story.append(Paragraph(f"Generated {esc(_now_str())}", center))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        f"<i>{esc(conf)} — Authorized assessment record. Planning and documentation only.</i>",
        center))
    story.append(PageBreak())

    story.append(Paragraph("Overview", h1))
    for k, v in (("Client", eng.get("client")), ("Authorization", eng.get("authorization_ref")),
                 ("Objective", _lbl(eng.get("objective"))), ("Box type", _lbl(eng.get("box_type"))),
                 ("Status", _lbl(eng.get("status")))):
        story.append(Paragraph(f"<b>{k}:</b> {esc(v)}", body))

    story.append(Paragraph("Rules of engagement", h1))
    for k, v in (("In-scope platforms", roe.get("scope_platforms")),
                 ("In-scope targets", roe.get("in_scope_targets")),
                 ("Restrictions", roe.get("restrictions")),
                 ("Time budget (h)", roe.get("time_budget_hours"))):
        val = ", ".join(map(str, v)) if isinstance(v, list) else v
        story.append(Paragraph(f"<b>{k}:</b> {esc(val)}", body))

    story.append(Paragraph("Executive summary", h1))
    story.append(Paragraph(
        f"Execution coverage: {cov.get('coverage_pct', 0)}% "
        f"({cov.get('steps_worked', 0)} of {cov.get('total_steps', 0)} planned steps worked). "
        f"{len(findings)} finding(s) recorded.", body))
    data = [["Severity", "Count"]] + [
        [_SEV_LABEL[s], str(counts[s])] for s in
        ("critical", "high", "medium", "low", "informational")]
    tbl = Table(data, colWidths=[2.5 * inch, 1.0 * inch])
    tstyle = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#"+_TEAL)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]
    for i, s in enumerate(("critical", "high", "medium", "low", "informational"), start=1):
        tstyle.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor("#" + _SEVERITY_COLOR[s])))
    tbl.setStyle(TableStyle(tstyle))
    story.append(Spacer(1, 6))
    story.append(tbl)

    # Attack-path roadmap.
    rm = _roadmap_drawing(ctx, 6.6 * inch)
    if rm is not None:
        story.append(Paragraph("Attack path", h1))
        story.append(Paragraph(
            "Nodes are plan steps (filled = worked, hollow/red = failed, dashed = "
            "skipped); the solid terracotta line is the path to the objective.", body))
        story.append(Spacer(1, 4))
        story.append(rm)

    story.append(Paragraph("Findings", h1))
    if not findings:
        story.append(Paragraph("No findings recorded.", body))
    for i, f in enumerate(findings, 1):
        sev = f.get("severity")
        color = "#" + _SEVERITY_COLOR.get(sev, "222222")
        tag = f"[{_SEV_LABEL.get(sev, '—')}] " if sev else ""
        story.append(Paragraph(
            f'<font color="{color}"><b>{i}. {esc(tag)}{esc(f.get("title") or "Untitled")}</b></font>', h2))
        if f.get("cvss_score") is not None:
            story.append(Paragraph(
                f"<b>CVSS:</b> {esc(f.get('cvss_score'))} {esc(f.get('cvss_vector') or '')}", body))
        for label, key in (("Status", "status"), ("Affected assets", "affected_assets"),
                           ("Description", "description"), ("Impact", "impact"),
                           ("Reproduction", "reproduction"), ("Remediation", "remediation"),
                           ("ATT&CK techniques", "technique_ids"), ("References", "references")):
            val = f.get(key)
            if not val:
                continue
            shown = ", ".join(map(str, val)) if isinstance(val, list) else val
            story.append(Paragraph(f"<b>{label}:</b> {esc(shown)}", body))
        ev = f.get("evidence") or []
        if ev:
            shown = "; ".join(
                f"{e.get('filename','?')} (sha256 {str(e.get('sha256',''))[:12]}…)" for e in ev)
            story.append(Paragraph(f"<b>Evidence:</b> {esc(shown)}", body))
        story.append(Spacer(1, 6))

    story.append(Paragraph("Execution log", h1))
    steps = ctx.get("steps", [])
    if not steps:
        story.append(Paragraph("No steps documented.", body))
    for s in steps:
        story.append(Paragraph(
            f"<b>{s.get('index', 0) + 1}. {esc(s.get('name') or s.get('technique_id'))} — "
            f"{_lbl(s.get('outcome'))}</b>", h2))
        meta_bits = [s.get("technique_id"), _lbl(s.get("tactic"))]
        if s.get("operator"):
            meta_bits.append(f"operator {s['operator']}")
        story.append(Paragraph("<i>" + esc(" · ".join(b for b in meta_bits if b)) + "</i>", body))
        if s.get("notes"):
            story.append(Paragraph(esc(s["notes"]), body))

    if branding.get("footer"):
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(f"<i>{esc(branding['footer'])}</i>", center))

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=letter,
                      leftMargin=0.9 * inch, rightMargin=0.9 * inch,
                      topMargin=0.9 * inch, bottomMargin=0.8 * inch).build(story)
    return buf.getvalue()
