"""
Finding reconciliation: cross-scanner dedup + evidence-based severity.

Two things make a scanner's output noisy enough that teams mute the gate — the
single biggest reason a gate gets deleted:

  1. Duplicates. Nuclei, Nikto, and the header scanner overlap; the same CVE or
     the same issue gets reported two or three times, inflating the count and
     making a clean run look alarming.

  2. Inflated severity. Scanners label generously. A wall of "HIGH" that is
     really mediums trains people to ignore the gate.

This module addresses both, conservatively:

  * Dedup merges only what is provably the same finding — a shared CVE, or an
    identical issue title once the scanner's name prefix is stripped. False
    merges hide real findings, which is worse than a duplicate, so the bar is
    "certain", not "probably". Merged findings keep every reporting scanner in
    a `sources` list, and corroboration by more than one tool is recorded.

  * Severity calibration re-derives a CVE finding's severity from its CVSS
    score — the standardised measure — instead of trusting each scanner's
    label, and floors a CISA-KEV (known-exploited) finding at HIGH. Findings
    with no CVE keep Bulwark's own curated severity. Every change records the
    original value and a short rationale, so nothing is silently rewritten.

Calibration only fires when CVE intelligence is present (i.e. enrichment ran);
with --no-enrich, severities are left exactly as the scanners set them.
"""
from __future__ import annotations

import re

from app.services.fingerprint import _normalise  # shared title normalisation

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}

# Scanner name prefixes stripped before comparing titles, so "Nuclei: X" and
# "Nikto: X" can be recognised as the same underlying issue X.
_PREFIX_RE = re.compile(r"^(nuclei|nikto|nmap|shodan)\s*[:\-]\s*", re.IGNORECASE)


def reconcile(findings: list[dict]) -> list[dict]:
    """Deduplicate, then calibrate severity. Returns a new list."""
    merged = _deduplicate(findings)
    for f in merged:
        _calibrate_severity(f)
    return merged


# ── Dedup ────────────────────────────────────────────────────────

def _dedup_key(f: dict):
    """A high-confidence identity for a finding.

    A CVE is the strongest join and is source-independent, so the same CVE
    reported by two scanners collapses to one. Otherwise the source-stripped,
    normalised title is used, which merges identically-worded issues (including
    a scanner emitting the same finding twice) without fuzzy guessing.
    """
    cve = (f.get("cve_id") or "").strip().upper()
    if cve:
        return ("cve", cve)
    title = f.get("title") or f.get("description") or ""
    stripped = _PREFIX_RE.sub("", title)
    return ("title", _normalise(stripped))


def _sev(f: dict) -> str:
    return (f.get("severity") or "INFO").upper()


def _pick_representative(group: list[dict]) -> dict:
    """Choose the richest finding in a duplicate group, deterministically.

    Preference: highest severity, then the most descriptive (longest
    description), then title alphabetically — so the result never depends on
    scan order.
    """
    return sorted(
        group,
        key=lambda f: (
            -_SEV_RANK.get(_sev(f), 0),
            -len(str(f.get("description") or "")),
            str(f.get("title") or ""),
        ),
    )[0]


def _deduplicate(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for f in findings:
        key = _dedup_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    out = []
    for key in order:
        group = groups[key]
        rep = dict(_pick_representative(group))

        # Union of every scanner that reported this issue.
        sources = sorted({str(f.get("source")) for f in group if f.get("source")})
        rep["sources"] = sources
        rep["corroborated"] = len(sources) > 1
        # The most severe assessment across duplicates wins pre-calibration; a
        # tool downplaying an issue shouldn't mask another flagging it high.
        rep["severity"] = max((_sev(f) for f in group), key=lambda s: _SEV_RANK.get(s, 0))
        if len(group) > 1:
            rep["duplicate_count"] = len(group)
        out.append(rep)
    return out


# ── Severity calibration ─────────────────────────────────────────

def cvss_to_severity(score: float) -> str:
    """CVSS v3 base score → severity band (the standard FIRST.org ranges)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _calibrate_severity(f: dict) -> None:
    """Re-derive severity from evidence, recording any change in place."""
    original = _sev(f)
    calibrated = original
    rationale = None

    cvss = f.get("cvss_score")
    if f.get("is_in_kev"):
        # Known to be exploited in the wild. Start from the CVSS band when we
        # have it (so a critical CVSS stays critical), then floor at HIGH —
        # a KEV entry is never a low-priority issue.
        base = cvss_to_severity(float(cvss)) if cvss is not None else original
        calibrated = base if _SEV_RANK[base] >= _SEV_RANK["HIGH"] else "HIGH"
        if calibrated != original:
            if cvss is not None and _SEV_RANK[base] >= _SEV_RANK["HIGH"]:
                rationale = f"aligned to CVSS {cvss} (CISA KEV, floor HIGH)"
            else:
                rationale = "raised to HIGH: listed in CISA KEV (known exploited)"
    elif cvss is not None:
        calibrated = cvss_to_severity(float(cvss))
        if calibrated != original:
            direction = "raised" if _SEV_RANK[calibrated] > _SEV_RANK[original] else "lowered"
            rationale = f"{direction} to match CVSS {cvss}"

    if calibrated != original:
        f["severity_original"] = original
        f["severity"] = calibrated
        f["severity_rationale"] = rationale
