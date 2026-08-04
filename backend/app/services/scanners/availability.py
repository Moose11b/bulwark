"""
Scanner availability reporting.

A security tool must never invent findings. Two situations previously produced
fabricated results:

  - a scanner could not run (binary missing, API key unset, tool errored), and
  - a scanner ran cleanly and found nothing,

and both returned hardcoded "demo" findings that were persisted, scored, and
displayed exactly like real detections. A clean target was reported as
vulnerable, and a broken toolchain was indistinguishable from a working one.

The rules now:
  - Found nothing  -> report nothing. Empty is a legitimate result.
  - Could not run  -> report an INFO finding saying so, so the gap is visible
                      rather than being read as "clean".
  - Demo fixtures  -> only when DEMO_MODE is explicitly enabled, and tagged in
                      the source field so they are never mistaken for real data.
"""
from app.config import get_settings


def demo_mode() -> bool:
    """True when the operator has explicitly opted into demo fixtures."""
    return get_settings().demo_mode


def demo_source(source: str) -> str:
    """Tag a demo finding's source so its origin is visible in the UI and API."""
    return source if source.endswith("-demo") else f"{source}-demo"


def unavailable(tool: str, source: str, reason: str, remediation: str) -> dict:
    """An INFO finding recording that a scanner could not run.

    Deliberately INFO and zero-weighted: it is a diagnostic about coverage,
    not a vulnerability, so it must not inflate the risk score.
    """
    return {
        "title": f"{tool} checks did not run",
        "source": source,
        "severity": "INFO",
        "cwe_id": None,
        "owasp_category": "A05",
        "killchain_phase": "reconnaissance",
        "mitre_technique_id": "T1595",
        "description": (
            f"{reason} No {tool} checks were performed against this target. "
            f"The absence of {tool} findings in this report does not mean the "
            f"target is free of the issues {tool} would detect."
        ),
        "evidence": f"{tool} unavailable in the scanner environment",
        "remediation": remediation,
        "references": [],
    }


def fallback(tool: str, source: str, reason: str, remediation: str,
             demo_results) -> list[dict]:
    """Demo fixtures when demo mode is on, otherwise an honest disclosure.

    `demo_results` is a zero-arg callable so the fixtures are only built when
    they are actually going to be used.
    """
    if demo_mode():
        return [
            {**f, "source": demo_source(f.get("source", source))}
            for f in demo_results()
        ]
    return [unavailable(tool, source, reason, remediation)]


def empty_or_demo(findings: list[dict], source: str, demo_results) -> list[dict]:
    """Pass real findings through untouched; only substitute demo data when a
    scan legitimately found nothing AND demo mode is on.

    Never used to paper over a failed scan — that is what fallback() is for.
    """
    if findings:
        return findings
    if demo_mode():
        return [
            {**f, "source": demo_source(f.get("source", source))}
            for f in demo_results()
        ]
    return []
