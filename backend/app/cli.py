#!/usr/bin/env python3
"""
Bulwark CLI — standalone vulnerability scanner for pipelines and local use.

Usage:
    bulwark scan <target> [options]

Examples:
    bulwark scan http://localhost:3000
    bulwark scan example.com --profile full --fail-on high
    bulwark scan example.com --sarif results.sarif --json results.json
    bulwark scan example.com --report-to $BULWARK_TOKEN   # send to hosted backend

Exit codes:
    0  scan completed, no findings at/above --fail-on threshold
    1  findings met/exceeded the --fail-on threshold (gate failed)
    2  scan error (target invalid, scanner crash, etc.)
"""
import argparse
import asyncio
import json
import sys
import os

__version__ = os.environ.get("BULWARK_VERSION", "dev")

# ANSI colours (disabled when not a TTY or NO_COLOR set)
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


SEV_COLOR = {
    "CRITICAL": "91", "HIGH": "31", "MEDIUM": "33", "LOW": "32", "INFO": "36",
}


def _print_banner():
    if _USE_COLOR:
        print(_c("  ⛨  BULWARK", "1;34") + _c("  ·  Fortify · Detect · Defend", "2;37"))
    else:
        print("  BULWARK  ·  Fortify · Detect · Defend")


def _print_table(result: dict):
    findings = result["findings"]
    summary = result["summary"]
    target = result["target"]

    print()
    print(f"  Target:   {target}")
    print(f"  Profile:  {result['profile']}")
    print(f"  Duration: {result['duration_seconds']}s")
    print(f"  Findings: {summary['total']}")
    print()

    if not findings:
        print(_c("  ✓ No findings.", "32"))
        return

    # Sort by severity, highest first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_sorted = sorted(
        findings, key=lambda f: order.get((f.get("severity") or "INFO").upper(), 9)
    )

    for f in findings_sorted:
        sev = (f.get("severity") or "INFO").upper()
        badge = _c(f"{sev:>8}", SEV_COLOR.get(sev, "37"))
        title = f.get("title", "Untitled")[:80]
        src = f.get("source", "")
        marks = ""
        if f.get("status") == "new":
            marks += " " + _c("NEW", "1;33")
        if f.get("suppressed"):
            marks += " " + _c("suppressed", "2;37")
        # Corroboration: show the tools that agreed, e.g. (nikto+nuclei).
        src_label = "+".join(f["sources"]) if f.get("corroborated") else src
        print(f"  {badge}  {title}{marks}  {_c(f'({src_label})', '2;37')}")
        extras = []
        if f.get("cve_id"):
            extras.append(f.get("cve_id"))
        if f.get("cvss_score"):
            extras.append(f"CVSS {f['cvss_score']}")
        if f.get("is_in_kev"):
            extras.append(_c("CISA-KEV", "91"))
        if f.get("owasp_category"):
            extras.append(f"OWASP {f['owasp_category']}")
        # Calibration is never silent: show the original severity and why.
        if f.get("severity_original"):
            extras.append(_c(f"severity {f['severity_original']}→{sev} "
                             f"({f.get('severity_rationale', '')})", "2;37"))
        if extras:
            print(f"            {_c('  '.join(str(e) for e in extras), '2;37')}")

    # Summary line
    print()
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = summary["by_severity"].get(sev, 0)
        if n:
            parts.append(_c(f"{n} {sev.lower()}", SEV_COLOR.get(sev, "37")))
    if "new" in summary:
        parts.append(_c(f"{summary['new']} new", "1;33"))
        parts.append(f"{summary['recurring']} recurring")
        parts.append(_c(f"{summary['resolved']} resolved", "32"))
    if summary.get("suppressed"):
        parts.append(_c(f"{summary['suppressed']} suppressed", "2;37"))
    print("  " + "  ".join(parts))


async def _send_to_backend(result: dict, token: str, api_url: str):
    """Optional: POST results to the hosted Bulwark backend (paid tier hook)."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{api_url}/api/ingest/scan-result",
                json=result,
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code in (200, 201, 202):
                print(_c(f"  ✓ Results sent to {api_url}", "32"))
            else:
                print(_c(f"  ! Backend returned {resp.status_code}", "33"))
    except Exception as e:
        print(_c(f"  ! Could not reach backend: {e}", "33"))


async def _run_scan(args) -> int:
    from app.services.standalone_engine import (
        StandaloneScanEngine, meets_threshold, new_findings_meet_threshold,
    )

    quiet = args.quiet or args.json == "-" or args.sarif == "-" or args.markdown == "-"

    if args.fail_on_new and not args.baseline:
        print(_c("  ✗ --fail-on-new requires --baseline", "31"), file=sys.stderr)
        return 2

    # Load gate inputs up front: a malformed baseline or suppression file
    # should fail fast (exit 2), not after a multi-minute scan.
    baseline = None
    if args.baseline:
        from app.services.baseline import load_baseline
        try:
            baseline = load_baseline(args.baseline)
        except ValueError as e:
            print(_c(f"  ✗ {e}", "31"), file=sys.stderr)
            return 2

    suppression_rules = []
    suppressions_path = args.suppressions
    if suppressions_path is None and os.path.exists(".bulwark.yml"):
        suppressions_path = ".bulwark.yml"
    if suppressions_path:
        from app.services.suppressions import load_suppressions, SuppressionError
        try:
            suppression_rules = load_suppressions(suppressions_path)
        except SuppressionError as e:
            print(_c(f"  ✗ {e}", "31"), file=sys.stderr)
            return 2

    def on_progress(pct, msg):
        if not quiet:
            sys.stderr.write(f"\r  [{pct:3d}%] {msg:<50}")
            sys.stderr.flush()

    engine = StandaloneScanEngine(
        enrich=not args.no_enrich,
        on_progress=on_progress if not quiet else None,
        allow_private=args.allow_private,
        api_spec=args.api_spec,
        api_include_writes=args.api_include_writes,
    )

    try:
        result = await engine.scan(args.target, profile=args.profile)
    except ValueError as e:
        print(_c(f"\n  ✗ {e}", "31"), file=sys.stderr)
        return 2
    except Exception as e:
        print(_c(f"\n  ✗ Scan failed: {e}", "31"), file=sys.stderr)
        return 2

    if not quiet:
        sys.stderr.write("\r" + " " * 70 + "\r")

    # Suppressions first (they decide what the gate can see), then the
    # baseline diff (a suppressed-but-present finding is not "resolved").
    if suppression_rules:
        from app.services.suppressions import apply_suppressions
        apply_suppressions(result, suppression_rules)
        if not quiet and result["summary"].get("suppressed"):
            n = result["summary"]["suppressed"]
            print(_c(f"  🤫 {n} finding(s) suppressed via {suppressions_path}", "2;37"))

    if baseline is not None:
        from app.services.baseline import apply_baseline
        apply_baseline(result, baseline)

    # ── Outputs ──────────────────────────────────────────────────
    # JSON
    if args.json:
        payload = json.dumps(result, indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w") as fh:
                fh.write(payload)
            if not quiet:
                print(_c(f"  ✓ JSON written to {args.json}", "32"))

    # SARIF
    if args.sarif:
        from app.services.sarif import to_sarif
        sarif = to_sarif(result, version=__version__)
        if args.sarif == "-":
            print(sarif)
        else:
            with open(args.sarif, "w") as fh:
                fh.write(sarif)
            if not quiet:
                print(_c(f"  ✓ SARIF written to {args.sarif}", "32"))

    # Human table (unless purely machine output)
    if not quiet and args.json != "-" and args.sarif != "-":
        _print_table(result)

    # Optional backend reporting (paid-tier seam)
    if args.report_to:
        await _send_to_backend(result, args.report_to, args.api_url)

    # ── Gate decision ────────────────────────────────────────────
    if args.fail_on_new:
        gate_failed = new_findings_meet_threshold(result["findings"], args.fail_on)
        scope = "new findings"
    else:
        gate_failed = meets_threshold(result["summary"], args.fail_on)
        scope = "findings"

    # Markdown summary (after the gate verdict so it can include it)
    if args.markdown:
        from app.services.summary_markdown import render_markdown
        md = render_markdown(
            result, fail_on=args.fail_on, gate_passed=not gate_failed,
            fail_on_new=args.fail_on_new,
        )
        if args.markdown == "-":
            print(md)
        else:
            with open(args.markdown, "w") as fh:
                fh.write(md)
            if not quiet:
                print(_c(f"  ✓ Markdown summary written to {args.markdown}", "32"))

    if gate_failed:
        if not quiet:
            print()
            print(_c(f"  ✗ Gate failed: {scope} at or above '{args.fail_on}' severity.", "1;31"))
        return 1

    if not quiet:
        print()
        print(_c(f"  ✓ Gate passed (threshold: {args.fail_on} on {scope}).", "1;32"))
    return 0


def _quiet_library_logs():
    """Silence library INFO/DEBUG logs (scanner internals) for CLI runs.

    The CLI has its own formatted output and a progress line; structlog's
    default INFO stream (e.g. `header_scanner.complete`) is just noise on top
    of it. Warnings and errors still surface. Only affects the CLI entrypoint,
    not the platform, which configures its own logging.
    """
    import logging
    try:
        import structlog
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING)
        )
    except Exception:
        pass


def main(argv=None):
    _quiet_library_logs()
    parser = argparse.ArgumentParser(
        prog="bulwark",
        description="Bulwark — standalone vulnerability scanner for CI/CD pipelines.",
    )
    parser.add_argument("--version", action="version",
                        version=f"bulwark {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a target")
    scan.add_argument("target", help="URL, domain, or IP to scan")
    scan.add_argument("--profile", default="web",
                      choices=["headers", "web", "network", "api", "full"],
                      help="Scan profile (default: web)")
    scan.add_argument("--api-spec", metavar="FILE_OR_URL",
                      help="OpenAPI 3.x / Swagger 2.0 spec (local file or URL) "
                           "to drive API endpoint scanning. Enables the API "
                           "scanner in any profile; without it the 'api'/'full' "
                           "profiles auto-discover a spec on the target.")
    scan.add_argument("--api-include-writes", action="store_true",
                      help="Also probe non-read methods (POST/PUT/PATCH/DELETE) "
                           "declared in the spec. Off by default — these can "
                           "mutate data. Use ONLY against disposable environments.")
    scan.add_argument("--fail-on", default="high",
                      choices=["critical", "high", "medium", "low", "never"],
                      help="Fail (exit 1) if findings at/above this severity (default: high)")
    scan.add_argument("--sarif", metavar="FILE",
                      help="Write SARIF output to FILE (use '-' for stdout)")
    scan.add_argument("--json", metavar="FILE",
                      help="Write JSON output to FILE (use '-' for stdout)")
    scan.add_argument("--baseline", metavar="FILE",
                      help="Previous scan JSON to diff against: findings are "
                           "marked new/recurring, and disappeared ones reported "
                           "as resolved")
    scan.add_argument("--fail-on-new", action="store_true",
                      help="Gate only on NEW findings vs --baseline (recurring "
                           "ones report but never fail the build)")
    scan.add_argument("--suppressions", metavar="FILE",
                      help="Suppression file (default: .bulwark.yml in the "
                           "current directory, if present)")
    scan.add_argument("--markdown", metavar="FILE",
                      help="Write a markdown scan summary to FILE (use '-' for "
                           "stdout) — made for $GITHUB_STEP_SUMMARY")
    scan.add_argument("--no-enrich", action="store_true",
                      help="Skip NVD/EPSS/KEV CVE enrichment (faster, offline)")
    scan.add_argument("--allow-private", action="store_true",
                      help="Allow scanning internal/loopback/private addresses. "
                           "ONLY for trusted local or CI scans you are authorised to run. "
                           "Disables SSRF protection — never use against untrusted input.")
    scan.add_argument("--quiet", action="store_true",
                      help="Suppress progress and table output")
    scan.add_argument("--report-to", metavar="TOKEN", default=os.environ.get("BULWARK_TOKEN"),
                      help="Send results to hosted Bulwark backend (token or $BULWARK_TOKEN)")
    scan.add_argument("--api-url", default=os.environ.get("BULWARK_API_URL", "https://api.bulwark.dev"),
                      help="Hosted backend URL (default: $BULWARK_API_URL)")

    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    _print_banner() if not args.quiet else None
    return asyncio.run(_run_scan(args))


if __name__ == "__main__":
    sys.exit(main())
