"""
Baseline diffing, suppressions, and gate decisions.

Pure-function tests: no database, network, or scanner binaries. This is the
logic that decides whether a build fails, so every branch of the decision —
new vs recurring, suppressed vs live, expired vs active suppressions — gets
pinned down here.
"""
import json
from datetime import date, timedelta

import pytest

from app.services.baseline import apply_baseline, load_baseline
from app.services.fingerprint import finding_fingerprint
from app.services.standalone_engine import (
    meets_threshold,
    new_findings_meet_threshold,
)
from app.services.suppressions import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
)
from app.services.summary_markdown import render_markdown


def _finding(title, severity="HIGH", source="nuclei", **extra):
    f = {"title": title, "severity": severity, "source": source, **extra}
    f["fingerprint"] = finding_fingerprint(f)
    return f


def _result(findings):
    counts = {s: 0 for s in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "target": "https://example.com",
        "profile": "web",
        "duration_seconds": 12.3,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": counts,
            "highest_severity": max(
                (f["severity"] for f in findings),
                key=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index,
                default="INFO",
            ),
        },
    }


# ── Baseline diffing ─────────────────────────────────────────────

def test_baseline_classifies_new_recurring_resolved():
    old = _result([
        _finding("Missing security header: CSP"),
        _finding("Open port 3306: MySQL", source="nmap"),
    ])
    new = _result([
        _finding("Missing security header: CSP"),        # recurring
        _finding("Sensitive path accessible: /.env"),    # new
    ])

    apply_baseline(new, old)

    by_title = {f["title"]: f for f in new["findings"]}
    assert by_title["Missing security header: CSP"]["status"] == "recurring"
    assert by_title["Sensitive path accessible: /.env"]["status"] == "new"
    assert new["summary"]["new"] == 1
    assert new["summary"]["recurring"] == 1
    assert new["summary"]["resolved"] == 1
    assert new["resolved_findings"][0]["title"] == "Open port 3306: MySQL"


def test_baseline_matches_reworded_finding_by_cve():
    old = _result([_finding("Apache thing (old wording)", cve_id="CVE-2024-1111")])
    new = _result([_finding("Apache vulnerability (new wording)", cve_id="CVE-2024-1111")])
    apply_baseline(new, old)
    assert new["findings"][0]["status"] == "recurring"
    assert new["summary"]["resolved"] == 0


def test_baseline_without_fingerprints_still_diffs():
    # Result files written before fingerprints were stamped must still work.
    old = _result([_finding("Missing security header: CSP")])
    for f in old["findings"]:
        f.pop("fingerprint")
    new = _result([_finding("Missing security header: CSP")])
    apply_baseline(new, old)
    assert new["findings"][0]["status"] == "recurring"


def test_load_baseline_rejects_garbage(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline(str(p))

    p2 = tmp_path / "wrong-shape.json"
    p2.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError, match="findings"):
        load_baseline(str(p2))

    with pytest.raises(ValueError, match="not found"):
        load_baseline(str(tmp_path / "missing.json"))


# ── Gate decisions ───────────────────────────────────────────────

def test_fail_on_new_ignores_recurring():
    result = _result([
        _finding("Recurring critical", "CRITICAL"),
        _finding("New low", "LOW"),
    ])
    baseline = _result([_finding("Recurring critical", "CRITICAL")])
    apply_baseline(result, baseline)

    # Plain gate fails on the recurring critical; the diff-aware gate does not.
    assert meets_threshold(result["summary"], "high") is True
    assert new_findings_meet_threshold(result["findings"], "high") is False
    # A new HIGH would still fail the diff-aware gate.
    result["findings"].append({**_finding("New high", "HIGH"), "status": "new"})
    assert new_findings_meet_threshold(result["findings"], "high") is True


def test_fail_on_new_respects_never_and_suppressions():
    findings = [{**_finding("New critical", "CRITICAL"), "status": "new"}]
    assert new_findings_meet_threshold(findings, "never") is False
    findings[0]["suppressed"] = True
    assert new_findings_meet_threshold(findings, "high") is False


# ── Suppressions ─────────────────────────────────────────────────

def _write_suppressions(tmp_path, body):
    p = tmp_path / ".bulwark.yml"
    p.write_text(body)
    return str(p)


def test_suppression_by_fingerprint_title_and_cve(tmp_path):
    f1 = _finding("Missing security header: X-Frame-Options")
    f2 = _finding("Outdated nginx", cve_id="CVE-2024-2222")
    f3 = _finding("Missing security header: CSP")
    result = _result([f1, f2, f3])

    path = _write_suppressions(tmp_path, f"""
suppressions:
  - fingerprint: {f1['fingerprint']}
    reason: "Set by the CDN in production"
  - cve: cve-2024-2222
    reason: "Patched build, banner not bumped"
""")
    apply_suppressions(result, load_suppressions(path))

    assert result["findings"][0]["suppressed"] is True
    assert result["findings"][1]["suppressed"] is True
    assert "suppressed" not in result["findings"][2]
    # Gate sees only the live finding
    assert result["summary"]["total"] == 1
    assert result["summary"]["suppressed"] == 2
    assert result["summary"]["by_severity"]["HIGH"] == 1


def test_suppression_title_glob(tmp_path):
    result = _result([
        _finding("Missing security header: X-Frame-Options"),
        _finding("Missing security header: CSP"),
        _finding("Open port 22: SSH", source="nmap"),
    ])
    path = _write_suppressions(tmp_path, """
suppressions:
  - title: "missing security header: *"
    reason: "Headers tracked in ticket SEC-42"
""")
    apply_suppressions(result, load_suppressions(path))
    assert result["summary"]["suppressed"] == 2
    assert result["summary"]["total"] == 1


def test_expired_suppression_stops_matching(tmp_path):
    f = _finding("Old accepted risk")
    result = _result([f])
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    path = _write_suppressions(tmp_path, f"""
suppressions:
  - fingerprint: {f['fingerprint']}
    reason: "Time-boxed acceptance"
    expires: {yesterday}
""")
    apply_suppressions(result, load_suppressions(path))
    assert "suppressed" not in result["findings"][0]
    assert result["summary"]["total"] == 1
    assert result["summary"]["suppressed"] == 0


def test_unexpired_suppression_matches(tmp_path):
    f = _finding("Accepted risk")
    result = _result([f])
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    path = _write_suppressions(tmp_path, f"""
suppressions:
  - fingerprint: {f['fingerprint']}
    reason: "Still accepted"
    expires: "{tomorrow}"
""")
    apply_suppressions(result, load_suppressions(path))
    assert result["findings"][0]["suppressed"] is True


def test_suppression_file_validation(tmp_path):
    with pytest.raises(SuppressionError, match="not found"):
        load_suppressions(str(tmp_path / "nope.yml"))

    p = _write_suppressions(tmp_path, "suppressions: {not: a list}")
    with pytest.raises(SuppressionError, match="list"):
        load_suppressions(p)

    p = _write_suppressions(tmp_path, """
suppressions:
  - fingerprint: abc123
""")
    with pytest.raises(SuppressionError, match="reason"):
        load_suppressions(p)

    p = _write_suppressions(tmp_path, """
suppressions:
  - reason: "no selector at all"
""")
    with pytest.raises(SuppressionError, match="fingerprint"):
        load_suppressions(p)

    p = _write_suppressions(tmp_path, """
suppressions:
  - fingerprint: abc123
    reason: "bad date"
    expires: not-a-date
""")
    with pytest.raises(SuppressionError, match="expires"):
        load_suppressions(p)


# ── SARIF integration ────────────────────────────────────────────

def test_sarif_carries_fingerprint_status_and_suppression():
    from app.services.sarif import to_sarif

    f1 = {**_finding("New finding"), "status": "new"}
    f2 = {**_finding("Suppressed finding"), "suppressed": True,
          "suppressed_reason": "Accepted: SEC-7"}
    sarif = json.loads(to_sarif(_result([f1, f2])))
    results = sarif["runs"][0]["results"]

    assert results[0]["partialFingerprints"]["bulwarkFingerprint/v1"] == f1["fingerprint"]
    assert results[0]["properties"]["baseline_status"] == "new"
    assert "suppressions" not in results[0]
    assert results[1]["suppressions"][0]["justification"] == "Accepted: SEC-7"


# ── Markdown summary ─────────────────────────────────────────────

def test_markdown_summary_renders_diff_and_suppressions():
    result = _result([
        _finding("New critical thing", "CRITICAL"),
        _finding("Recurring medium thing", "MEDIUM"),
    ])
    baseline = _result([
        _finding("Recurring medium thing", "MEDIUM"),
        _finding("Fixed thing", "HIGH"),
    ])
    apply_baseline(result, baseline)
    md = render_markdown(result, fail_on="high", gate_passed=False, fail_on_new=True)

    assert "❌ **Gate failed**" in md
    assert "new findings" in md
    assert "1 new" in md and "1 recurring" in md and "1 resolved" in md
    assert "New critical thing" in md
    assert "Fixed thing" in md          # in the resolved section
    # New findings sort above recurring ones regardless of severity order
    assert md.index("New critical thing") < md.index("Recurring medium thing")


def test_markdown_summary_plain_run():
    result = _result([_finding("Only finding", "LOW")])
    md = render_markdown(result, fail_on="high", gate_passed=True)
    assert "✅ **Gate passed**" in md
    assert "Only finding" in md
    assert "Since baseline" not in md
