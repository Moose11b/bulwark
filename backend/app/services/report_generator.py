"""
PDF report generator for Bulwark.
Uses WeasyPrint to render a Jinja2 HTML template to a pixel-perfect PDF.
Supports two report types:
  - 'executive'  → cover + summary + top 10 findings
  - 'full'       → everything including all findings with evidence
"""
import os
import math
import asyncio
import structlog
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

logger = structlog.get_logger()

TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORTS_DIR  = Path("/app/reports")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]

RISK_COLOR_MAP = [
    (75, "#DC2626"),   # critical — red
    (50, "#EA580C"),   # high — orange
    (25, "#CA8A04"),   # medium — amber
    (0,  "#16A34A"),   # low — green
]

SEV_HEADER_BG = {
    "CRITICAL": "#FFF1F2",
    "HIGH":     "#FFF7ED",
    "MEDIUM":   "#FEFCE8",
    "LOW":      "#F0FDF4",
    "INFO":     "#EFF6FF",
    "PASS":     "#F8FAFC",
}

KC_PHASES = [
    {"phase": 1, "name": "Reconnaissance",   "icon": "🔍", "id": "reconnaissance"},
    {"phase": 2, "name": "Weaponization",    "icon": "⚙️",  "id": "weaponization"},
    {"phase": 3, "name": "Delivery",         "icon": "📦",  "id": "delivery"},
    {"phase": 4, "name": "Exploitation",     "icon": "⚡",  "id": "exploitation"},
    {"phase": 5, "name": "Installation",     "icon": "💾",  "id": "installation"},
    {"phase": 6, "name": "Command & Control","icon": "📡",  "id": "command_control"},
    {"phase": 7, "name": "Actions",          "icon": "🎯",  "id": "actions"},
]

DEFENDER_ACTIONS = {
    "reconnaissance":  "Monitor scanning. Minimise public attack surface.",
    "weaponization":   "Track threat intelligence. Understand adversary TTPs.",
    "delivery":        "Patch exposed services. Analyse delivery vectors.",
    "exploitation":    "Patch vulnerabilities. Deploy WAF/IPS.",
    "installation":    "Application allowlisting. Audit startup items.",
    "command_control": "Block C2 traffic. Monitor DNS and outbound.",
    "actions":         "DLP controls. Immutable backups. Encrypt sensitive data.",
}

HEAT_COLORS = [
    (80, "#DC2626", "#FEE2E2"),
    (60, "#EA580C", "#FFEDD5"),
    (40, "#CA8A04", "#FEF9C3"),
    (20, "#2563EB", "#EFF6FF"),
    (0,  "#94A3B8", "#F8FAFC"),
]


def _risk_color(score: float) -> str:
    for threshold, color in RISK_COLOR_MAP:
        if score >= threshold:
            return color
    return "#16A34A"


def _heat_color(pct: float) -> tuple[str, str]:
    for threshold, color, bg in HEAT_COLORS:
        if pct >= threshold:
            return color, bg
    return "#94A3B8", "#F8FAFC"


async def generate(scan_id: str, report_type: str = "full", user_id: str = "") -> dict:
    """Main entry point called by the Celery task."""
    from app.database import AsyncSessionLocal
    from app.models import Scan, Finding
    from app.services.analysis import (
        build_owasp_report, build_killchain_report,
        classify_vulnerability, classify_to_phase,
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = REPORTS_DIR / f"{scan_id}.pdf"

    async with AsyncSessionLocal() as db:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        raw_findings = findings_result.scalars().all()

    # Convert findings to dicts
    finding_dicts = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "source": f.source,
            "cvss_score": f.cvss_score or 0.0,
            "epss_score": f.epss_score,
            "is_in_kev": f.is_in_kev,
            "owasp_category": f.owasp_category,
            "killchain_phase": f.killchain_phase,
            "pci_dss": f.pci_dss or [],
            "iso_27001": f.iso_27001 or [],
            "nist_csf": f.nist_csf or [],
            "cis_v8": getattr(f, "cis_v8", None) or [],
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
        }
        for f in raw_findings
    ]

    # Sort by severity
    sev_idx = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    finding_dicts.sort(key=lambda f: sev_idx.get(f["severity"], 99))

    # Add header bg colour per finding
    for f in finding_dicts:
        f["header_bg"] = SEV_HEADER_BG.get(f["severity"], "#F8FAFC")

    # Severity counts
    counts = {s: sum(1 for f in finding_dicts if f["severity"] == s) for s in SEVERITY_ORDER}

    # OWASP report
    owasp = build_owasp_report(scan_id, finding_dicts)

    # Kill chain report
    kc = build_killchain_report(scan_id, finding_dicts)

    # Phase data for template
    phase_count_map = {p["id"]: p["count"] for p in kc["phases"]}
    max_heat = max((p["heat"] for p in kc["phases"]), default=1) or 1
    kc_phases_ctx = []
    for p in KC_PHASES:
        count = phase_count_map.get(p["id"], 0)
        heat_pct = sum(
            ph["heat"] for ph in kc["phases"] if ph["id"] == p["id"]
        ) / max_heat * 100 if max_heat else 0
        color, bg = _heat_color(heat_pct)
        kc_phases_ctx.append({
            **p,
            "count": count,
            "heat_pct": round(heat_pct),
            "color": color if count > 0 else "#CBD5E1",
            "bg": bg if count > 0 else "#F8FAFC",
            "defender_action": DEFENDER_ACTIONS.get(p["id"], ""),
        })

    # Compliance summary
    pci_controls  = len(set(c for f in finding_dicts for c in f["pci_dss"]))
    iso_controls  = len(set(c for f in finding_dicts for c in f["iso_27001"]))
    nist_controls = len(set(c for f in finding_dicts for c in f["nist_csf"]))
    cis_controls  = len(set(c for f in finding_dicts for c in f["cis_v8"]))

    from app.services.compliance import CONTROL_MAPPING_DISCLAIMER

    # Scan metadata
    risk_score = round(scan.risk_score or 0)
    duration = "—"
    if scan.started_at and scan.completed_at:
        secs = int((scan.completed_at - scan.started_at).total_seconds())
        duration = f"{secs // 60}m {secs % 60}s"

    scan_ctx = {
        "target": scan.target,
        "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else scan.scan_type,
        "created_at_fmt": scan.created_at.strftime("%d %b %Y %H:%M UTC") if scan.created_at else "—",
        "duration": duration,
    }

    # Top findings for executive summary
    top_findings = finding_dicts[:10]

    # Build template context
    ctx = {
        "scan": scan_ctx,
        "report_type": "Full" if report_type == "full" else "Executive",
        "risk_score": risk_score,
        "risk_color": _risk_color(risk_score),
        "counts": counts,
        "findings": finding_dicts if report_type == "full" else [],
        "top_findings": top_findings,
        "owasp_categories": owasp["categories"],
        "owasp_hit": owasp["categories_hit"],
        "kc_phases": kc_phases_ctx,
        "highest_phase": kc["highest_phase"],
        "highest_phase_name": kc["highest_phase_name"],
        "exposed_phases": kc["exposed_phases"],
        "pci_controls": pci_controls,
        "iso_controls": iso_controls,
        "nist_controls": nist_controls,
        "cis_controls": cis_controls,
        "compliance_disclaimer": CONTROL_MAPPING_DISCLAIMER,
    }

    # Render HTML
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["truncate"] = lambda s, n: (s[:n] + "…") if len(s) > n else s
    template = env.get_template("report.html")
    html = template.render(**ctx)

    # Convert to PDF via WeasyPrint (run in executor to avoid blocking event loop)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _render_pdf, html, str(output_path))

    logger.info(
        "report.generated",
        scan_id=scan_id,
        report_type=report_type,
        findings=len(finding_dicts),
        path=str(output_path),
    )

    return {
        "scan_id": scan_id,
        "report_type": report_type,
        "path": str(output_path),
        "findings": len(finding_dicts),
        "risk_score": risk_score,
    }


def _render_pdf(html: str, output_path: str) -> None:
    """Synchronous WeasyPrint render — called from an executor thread."""
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        font_config = FontConfiguration()
        HTML(string=html).write_pdf(
            output_path,
            font_config=font_config,
        )
    except ImportError:
        # WeasyPrint not available (e.g. local dev without system deps)
        # Fall back to saving raw HTML for inspection
        html_path = output_path.replace(".pdf", ".html")
        with open(html_path, "w") as f:
            f.write(html)
        logger.warning("report.weasyprint_missing", html_saved=html_path)
        raise RuntimeError(
            "WeasyPrint is not available. Install system dependencies: "
            "apt-get install libpango-1.0-0 libpangoft2-1.0-0 libcairo2"
        )
