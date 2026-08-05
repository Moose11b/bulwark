"""
Scanner output parsing and classification.

These need no database, network, or scanner binaries — they feed captured tool
output through the parsers. This is where the risk actually lives: a parser
that quietly drops a CVE, or invents a finding out of a timestamp line, is
invisible in an end-to-end run because the scan still "succeeds".
"""
import json

from app.services.analysis import (
    classify_to_phase,
    classify_vulnerability,
    map_compliance,
)
from app.services.scanners.nikto_scanner import (
    _classify_owasp,
    _classify_severity,
    _parse_nikto_output,
)
from app.services.scanners.nuclei_scanner import (
    _extract_cve,
    _map_tags,
    _parse_nuclei_jsonl,
)

# ── Nikto ────────────────────────────────────────────────────────

# Trimmed but structurally faithful nikto -Format txt output.
NIKTO_OUTPUT = """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        443
+ Start Time:         2024-01-15 10:23:45 (GMT0)
---------------------------------------------------------------------------
+ The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /admin/: Admin login page/section found.
+ 8724 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-01-15 10:31:02 (GMT0) (437 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""


def _titles(findings):
    return " | ".join(f["title"] for f in findings)


def test_nikto_extracts_real_findings():
    findings = _parse_nikto_output(NIKTO_OUTPUT, "https://example.com")
    joined = _titles(findings).lower()
    assert "anti-clickjacking" in joined
    assert "osvdb-3233" in joined or "apache default file" in joined
    assert "admin login page" in joined


def test_nikto_does_not_invent_findings_from_timestamps():
    """'+ End Time: ...' is metadata, not a vulnerability."""
    findings = _parse_nikto_output(NIKTO_OUTPUT, "https://example.com")
    offenders = [f["title"] for f in findings if "end time" in f["title"].lower()]
    assert not offenders, f"scan timestamp reported as a finding: {offenders}"


def test_nikto_does_not_invent_findings_from_the_request_summary():
    """'+ 8724 requests: 0 error(s)...' is a run summary, not a vulnerability."""
    findings = _parse_nikto_output(NIKTO_OUTPUT, "https://example.com")
    offenders = [f["title"] for f in findings if "requests:" in f["title"].lower()]
    assert not offenders, f"request summary reported as a finding: {offenders}"


def test_nikto_excludes_target_metadata():
    findings = _parse_nikto_output(NIKTO_OUTPUT, "https://example.com")
    joined = _titles(findings).lower()
    for meta in ("target ip", "target hostname", "target port", "start time"):
        assert meta not in joined, f"{meta!r} leaked into findings"


def test_nikto_empty_output_yields_no_findings():
    assert _parse_nikto_output("", "https://example.com") == []
    assert _parse_nikto_output("\n\n   \n", "https://example.com") == []


def test_nikto_every_finding_has_the_required_shape():
    for f in _parse_nikto_output(NIKTO_OUTPUT, "https://example.com"):
        for key in ("title", "source", "severity", "description", "remediation"):
            assert f.get(key), f"missing {key} in {f}"
        assert f["source"] == "nikto"
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_nikto_severity_classification():
    assert _classify_severity("SQL injection in login form") == "CRITICAL"
    assert _classify_severity("Directory traversal found") == "HIGH"
    assert _classify_severity("Server version disclosure") == "MEDIUM"
    assert _classify_severity("Directory listing enabled") == "LOW"
    assert _classify_severity("something entirely unremarkable") == "INFO"


def test_nikto_owasp_mapping_always_returns_a_triple():
    owasp, phase, mitre = _classify_owasp("sql injection")
    assert (owasp, phase) == ("A03", "exploitation")
    # Unknown text must still yield a usable default, never None.
    owasp, phase, mitre = _classify_owasp("no keyword here at all")
    assert owasp and phase and mitre


# ── Nuclei ───────────────────────────────────────────────────────

def _jsonl(*items):
    return "\n".join(json.dumps(i) for i in items)


NUCLEI_CVE_IN_TEMPLATE_ID = {
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Apache Log4j2 RCE",
        "severity": "critical",
        "description": "Log4Shell remote code execution.",
        "tags": "cve,rce,log4j",
    },
    "matched-at": "https://example.com/",
}

NUCLEI_CVE_IN_CLASSIFICATION = {
    "template-id": "some-template",
    "info": {
        "name": "Templated CVE",
        "severity": "high",
        "tags": "cve",
        "classification": {"cve-id": ["CVE-2014-0160"], "cwe-id": ["CWE-119"]},
    },
    "matched-at": "https://example.com/",
}


def test_nuclei_keeps_cve_found_in_the_template_id():
    """A CVE in the template id must survive even with no classification block.

    Most CVE templates carry the identifier only in template-id. Losing it
    means the finding is stored with cve_id NULL and never gets NVD, EPSS, or
    KEV enrichment — the scan looks fine while the intelligence silently
    goes missing.
    """
    findings = _parse_nuclei_jsonl(_jsonl(NUCLEI_CVE_IN_TEMPLATE_ID), "https://example.com")
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2021-44228"


def test_nuclei_keeps_cve_from_the_classification_block():
    findings = _parse_nuclei_jsonl(_jsonl(NUCLEI_CVE_IN_CLASSIFICATION), "https://example.com")
    assert findings[0]["cve_id"] == "CVE-2014-0160"
    assert findings[0]["cwe_id"] == "CWE-119"


def test_nuclei_severity_mapping():
    rows = [
        {**NUCLEI_CVE_IN_TEMPLATE_ID, "info": {**NUCLEI_CVE_IN_TEMPLATE_ID["info"], "severity": s}}
        for s in ("critical", "high", "medium", "low", "info", "unknown")
    ]
    got = [f["severity"] for f in _parse_nuclei_jsonl(_jsonl(*rows), "https://example.com")]
    assert got == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFO"]


def test_nuclei_skips_malformed_lines_without_losing_valid_ones():
    raw = "\n".join([
        "not json at all",
        json.dumps(NUCLEI_CVE_IN_TEMPLATE_ID),
        "{ truncated",
        "",
    ])
    findings = _parse_nuclei_jsonl(raw, "https://example.com")
    assert len(findings) == 1, "a malformed line should not discard valid findings"


def test_nuclei_empty_output_yields_no_findings():
    assert _parse_nuclei_jsonl("", "https://example.com") == []


def test_nuclei_references_are_always_a_list():
    row = {**NUCLEI_CVE_IN_TEMPLATE_ID}
    row["info"] = {**row["info"], "reference": "https://example.com/advisory"}
    findings = _parse_nuclei_jsonl(_jsonl(row), "https://example.com")
    assert isinstance(findings[0]["references"], list)


def test_nuclei_tag_mapping():
    assert _map_tags(["sqli"])[0] == "A03"
    assert _map_tags(["ssrf"])[0] == "A10"
    # Unknown tags still return a usable default triple.
    owasp, phase, mitre = _map_tags(["nonsense-tag"])
    assert owasp and phase and mitre


def test_nuclei_cve_extraction_is_case_insensitive():
    assert _extract_cve("cve-2021-44228", []) == "CVE-2021-44228"
    assert _extract_cve("no-cve-here", ["tag"]) is None


# ── Classification / compliance ──────────────────────────────────

def test_classifiers_accept_sparse_findings():
    """Scanner dicts vary; classifiers must not raise on missing keys."""
    for finding in ({}, {"title": "x"}, {"description": None, "title": None}):
        cat, _ = classify_vulnerability(finding)
        phase, _ = classify_to_phase(finding)
        assert cat and phase


def test_compliance_mapping_returns_all_frameworks():
    mapped = map_compliance({"title": "SQL injection", "severity": "CRITICAL"})
    for framework in ("pci_dss", "iso_27001", "nist_csf", "cis_v8"):
        assert framework in mapped
        assert isinstance(mapped[framework], list)
