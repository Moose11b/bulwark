"""
Finding reconciliation: dedup + severity calibration.

Pure functions. This changes finding counts and severities, which flow straight
into the gate decision, so both the merging (must not hide a distinct finding)
and the calibration (must not silently rewrite) are pinned down here.
"""
from app.services.reconciliation import (
    reconcile,
    cvss_to_severity,
    _deduplicate,
)


def _f(title, severity="MEDIUM", source="nuclei", **extra):
    return {"title": title, "severity": severity, "source": source, **extra}


# ── Dedup ────────────────────────────────────────────────────────

def test_same_cve_across_scanners_merges():
    findings = [
        _f("Nuclei: Apache RCE", "HIGH", "nuclei", cve_id="CVE-2021-41773"),
        _f("Nikto: Apache path traversal", "MEDIUM", "nikto", cve_id="cve-2021-41773"),
    ]
    out = _deduplicate(findings)
    assert len(out) == 1
    assert out[0]["sources"] == ["nikto", "nuclei"]
    assert out[0]["corroborated"] is True
    # Most severe assessment wins the merge
    assert out[0]["severity"] == "HIGH"
    assert out[0]["duplicate_count"] == 2


def test_identical_title_after_prefix_strip_merges():
    findings = [
        _f("Nuclei: Directory listing enabled", "LOW", "nuclei"),
        _f("Nikto: Directory listing enabled", "LOW", "nikto"),
    ]
    out = _deduplicate(findings)
    assert len(out) == 1
    assert out[0]["sources"] == ["nikto", "nuclei"]


def test_distinct_findings_are_not_merged():
    findings = [
        _f("Missing security header: CSP", "HIGH", "header_scanner"),
        _f("Missing security header: HSTS", "MEDIUM", "header_scanner"),
        _f("Nuclei: Some CVE", "HIGH", "nuclei", cve_id="CVE-2020-0001"),
    ]
    out = _deduplicate(findings)
    assert len(out) == 3       # nothing collapses


def test_different_cves_stay_separate():
    findings = [
        _f("Nuclei: A", "HIGH", "nuclei", cve_id="CVE-2021-1"),
        _f("Nuclei: B", "HIGH", "nuclei", cve_id="CVE-2021-2"),
    ]
    assert len(_deduplicate(findings)) == 2


def test_representative_is_deterministic_richest():
    # Same title, different detail; the more descriptive one is kept.
    findings = [
        _f("Nuclei: X", "MEDIUM", "nuclei", description="short"),
        _f("Nuclei: X", "MEDIUM", "nuclei", description="a much longer description"),
    ]
    out = _deduplicate(findings)
    assert out[0]["description"] == "a much longer description"


# ── Severity calibration ─────────────────────────────────────────

def test_cvss_bands():
    assert cvss_to_severity(9.8) == "CRITICAL"
    assert cvss_to_severity(7.0) == "HIGH"
    assert cvss_to_severity(5.5) == "MEDIUM"
    assert cvss_to_severity(0.5) == "LOW"
    assert cvss_to_severity(0.0) == "INFO"


def test_inflated_severity_is_lowered_to_cvss():
    out = reconcile([_f("Nuclei: overrated", "CRITICAL", "nuclei",
                        cve_id="CVE-2020-1", cvss_score=5.4)])
    assert out[0]["severity"] == "MEDIUM"
    assert out[0]["severity_original"] == "CRITICAL"
    assert "lowered" in out[0]["severity_rationale"]


def test_underrated_severity_is_raised_to_cvss():
    out = reconcile([_f("Nuclei: underrated", "LOW", "nuclei",
                        cve_id="CVE-2020-2", cvss_score=9.1)])
    assert out[0]["severity"] == "CRITICAL"
    assert out[0]["severity_original"] == "LOW"
    assert "raised" in out[0]["severity_rationale"]


def test_kev_floors_at_high():
    out = reconcile([_f("Nuclei: exploited", "LOW", "nuclei",
                        cve_id="CVE-2020-3", is_in_kev=True)])
    assert out[0]["severity"] == "HIGH"
    assert "KEV" in out[0]["severity_rationale"]


def test_kev_with_critical_cvss_stays_critical():
    out = reconcile([_f("Nuclei: bad", "MEDIUM", "nuclei",
                        cve_id="CVE-2020-4", is_in_kev=True, cvss_score=9.5)])
    assert out[0]["severity"] == "CRITICAL"


def test_no_cve_severity_is_untouched():
    out = reconcile([_f("Missing security header: CSP", "HIGH", "header_scanner")])
    assert out[0]["severity"] == "HIGH"
    assert "severity_original" not in out[0]


def test_reconcile_dedups_then_calibrates():
    # Two scanners flag the same CVE at different (inflated) severities; the
    # merge takes the max, then CVSS calibration sets the real band.
    findings = [
        _f("Nuclei: thing", "CRITICAL", "nuclei", cve_id="CVE-2021-9", cvss_score=5.0),
        _f("Nikto: thing", "HIGH", "nikto", cve_id="CVE-2021-9"),
    ]
    out = reconcile(findings)
    assert len(out) == 1
    assert out[0]["corroborated"] is True
    assert out[0]["severity"] == "MEDIUM"          # CVSS 5.0 band
    assert out[0]["severity_original"] == "CRITICAL"
