"""
Comparator unit tests.

Pure and network-free: they feed synthetic Bulwark and ZAP payloads through the
normalisers and scorer. The scoring logic decides the headline benchmark
numbers, so a regression here would silently misreport detection rates — worth
pinning down.

Run: python -m pytest benchmarks/test_compare.py
"""
import compare


BULWARK = {
    "findings": [
        {"title": "Broken object-level authorization: GET /api/users/{id}",
         "severity": "CRITICAL", "owasp_category": "A01", "cwe_id": "CWE-639"},
        {"title": "Authentication not enforced: GET /api/admin/config",
         "severity": "HIGH", "owasp_category": "A07", "cwe_id": "CWE-306"},
        {"title": "Missing security header: Content-Security-Policy",
         "severity": "HIGH", "owasp_category": "A03", "cwe_id": "CWE-79"},
        {"title": "Suppressed thing", "severity": "HIGH", "owasp_category": "A01",
         "suppressed": True},
    ]
}

ZAP = {
    "site": [{
        "@name": "http://t", "alerts": [
            {"name": "CSP Header Not Set", "riskcode": "2", "cweid": "693",
             "tags": {"OWASP_2021_A05": "x"},
             "instances": [{"uri": "http://t/", "method": "GET"}]},
            {"name": "Application Error Disclosure", "riskcode": "2", "cweid": "209",
             "instances": [{"uri": "http://t/api/search?q=%27", "method": "GET"}]},
        ]
    }]
}

GROUND_TRUTH = {
    "planted": [
        {"id": "bola", "title": "BOLA on users", "owasp": "A01", "severity": "CRITICAL",
         "match": {"keywords": ["object-level", "bola", "idor"]}},
        {"id": "hdrs", "title": "Missing headers", "owasp": "A05", "severity": "MEDIUM",
         "match": {"owasp": ["A05"], "keywords": ["security header", "content-security-policy", "csp"]}},
    ],
    "controls": [
        {"id": "acct", "endpoint": "GET /api/account/{id}",
         "false_positive_keywords": ["/api/account"], "false_positive_owasp": ["A07"]},
    ],
}


def test_normalize_bulwark_skips_suppressed_and_extracts_fields():
    fs = compare.normalize_bulwark(BULWARK)
    assert len(fs) == 3                      # suppressed one dropped
    bola = fs[0]
    assert bola.severity == "CRITICAL"
    assert bola.owasp == "A01"
    assert bola.cwe == "639"
    assert bola.endpoint == "GET /api/users/{id}"


def test_normalize_zap_maps_severity_and_owasp():
    fs = compare.normalize_zap(ZAP)
    csp = fs[0]
    assert csp.severity == "MEDIUM"          # riskcode 2
    assert csp.owasp == "A05"                # from OWASP tag
    err = fs[1]
    assert err.owasp == "A05"                # from CWE-209 map (no tag)
    assert "/api/search" in err.endpoint


def test_ground_truth_scoring_detects_and_rates():
    fs = compare.normalize_bulwark(BULWARK)
    score = compare.score_against_ground_truth(fs, GROUND_TRUTH)
    assert score["planted_total"] == 2
    assert score["detected"] == 2            # BOLA + headers
    assert score["detection_rate"] == 1.0
    assert score["false_positives"] == []


def test_zap_partial_detection():
    fs = compare.normalize_zap(ZAP)
    score = compare.score_against_ground_truth(fs, GROUND_TRUTH)
    # ZAP finds the header issue but not the BOLA (no spec, black-box)
    assert score["detected"] == 1
    assert score["detection_rate"] == 0.5
    detected_ids = {d["id"] for d in score["detected_items"]}
    assert "hdrs" in detected_ids
    assert "bola" not in detected_ids


def test_false_positive_on_control_is_counted():
    fp_finding = [compare.Finding(
        tool="x", name="Authentication not enforced: GET /api/account/{id}",
        severity="HIGH", owasp="A07", cwe="306", endpoint="GET /api/account/{id}")]
    score = compare.score_against_ground_truth(fp_finding, GROUND_TRUTH)
    assert len(score["false_positives"]) == 1
    assert score["false_positives"][0]["control"] == "acct"


def test_report_and_markdown_render():
    report = compare.build_report(
        "vulnapi",
        compare.normalize_bulwark(BULWARK),
        compare.normalize_zap(ZAP),
        GROUND_TRUTH,
        {"bulwark": 0.3, "zap": 42.0},
    )
    md = compare.render_markdown(report)
    assert "Detection rate vs. ground truth" in md
    assert "100%" in md          # bulwark 2/2
    assert "50%" in md           # zap 1/2
    assert "verbosity, not quality" in md
