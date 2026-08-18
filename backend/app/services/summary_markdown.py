"""
Markdown scan summary.

Rendered into $GITHUB_STEP_SUMMARY by the Action (or anywhere via
`--markdown`), so the verdict is readable on the PR itself without opening
logs or the Security tab. GitHub-flavored markdown, no HTML.
"""

_SEV_EMOJI = {
    "CRITICAL": "🟣", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵",
}

_STATUS_LABEL = {"new": "🆕 new", "recurring": "recurring"}

# Keep the table digestible on a PR; the full list is in the JSON/SARIF.
_MAX_ROWS = 20


def _md_escape(text: str) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(result: dict, *, fail_on: str, gate_passed: bool,
                    fail_on_new: bool = False) -> str:
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    diffed = "new" in summary

    lines = []
    verdict = "✅ **Gate passed**" if gate_passed else "❌ **Gate failed**"
    scope = "new findings" if fail_on_new else "findings"
    lines.append("## ⛨ Bulwark scan")
    lines.append("")
    lines.append(f"{verdict} — threshold: `{fail_on}` on {scope}.")
    lines.append("")
    lines.append(f"**Target:** `{result.get('target', '?')}` · "
                 f"**Profile:** `{result.get('profile', '?')}` · "
                 f"**Duration:** {result.get('duration_seconds', '?')}s")
    lines.append("")

    by_sev = summary.get("by_severity", {})
    sev_cells = "  ·  ".join(
        f"{_SEV_EMOJI[s]} {by_sev.get(s, 0)} {s.lower()}"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if by_sev.get(s, 0)
    ) or "none"
    lines.append(f"**Findings:** {summary.get('total', 0)} ({sev_cells})")

    counters = []
    if diffed:
        counters.append(f"🆕 {summary.get('new', 0)} new")
        counters.append(f"🔁 {summary.get('recurring', 0)} recurring")
        counters.append(f"✅ {summary.get('resolved', 0)} resolved")
    if summary.get("suppressed"):
        counters.append(f"🤫 {summary['suppressed']} suppressed")
    if counters:
        lines.append("")
        label = "**Since baseline:** " if diffed else ""
        lines.append(label + "  ·  ".join(counters))

    live = [f for f in findings if not f.get("suppressed")]
    if diffed:
        # New findings are what this PR needs to look at; lead with them.
        live.sort(key=lambda f: (f.get("status") != "new", _sev_rank(f)))
    else:
        live.sort(key=_sev_rank)

    if live:
        lines.append("")
        status_col = " Status |" if diffed else ""
        lines.append(f"| Severity |{status_col} Finding | Source |")
        lines.append(f"|---|{'---|' if diffed else ''}---|---|")
        for f in live[:_MAX_ROWS]:
            sev = (f.get("severity") or "INFO").upper()
            row = [f"{_SEV_EMOJI.get(sev, '')} {sev}"]
            if diffed:
                row.append(_STATUS_LABEL.get(f.get("status"), f.get("status") or ""))
            title = _md_escape(f.get("title", "Untitled"))
            if f.get("cve_id"):
                title += f" ({f['cve_id']})"
            row.append(title)
            row.append(_md_escape(f.get("source", "")))
            lines.append("| " + " | ".join(row) + " |")
        if len(live) > _MAX_ROWS:
            lines.append("")
            lines.append(f"…and {len(live) - _MAX_ROWS} more — see the SARIF/JSON output.")

    resolved = result.get("resolved_findings", [])
    if resolved:
        lines.append("")
        lines.append("<details><summary>✅ Resolved since baseline "
                     f"({len(resolved)})</summary>")
        lines.append("")
        for r in resolved[:_MAX_ROWS]:
            lines.append(f"- {_md_escape(r.get('title'))} "
                         f"({(r.get('severity') or 'INFO').upper()})")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    return "\n".join(lines)


def _sev_rank(f: dict) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get((f.get("severity") or "INFO").upper(), 9)
