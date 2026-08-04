"""
SARIF 2.1.0 formatter.

Converts Bulwark findings into the Static Analysis Results Interchange
Format so they render natively in GitHub's Security tab (code scanning
alerts) and GitLab's security dashboard. SARIF is the lingua franca for
CI security tooling — emitting it is what makes Bulwark a first-class
pipeline citizen rather than just log output.
"""
import json

# Bulwark severity → SARIF level + security-severity (0-10 for GitHub)
SEVERITY_TO_SARIF = {
    "CRITICAL": ("error", "9.5"),
    "HIGH":     ("error", "8.0"),
    "MEDIUM":   ("warning", "5.5"),
    "LOW":      ("note", "3.0"),
    "INFO":     ("note", "1.0"),
}


def _rule_id(finding: dict) -> str:
    """Stable rule ID per finding type for grouping in the Security tab."""
    source = finding.get("source", "bulwark")
    cwe = finding.get("cwe_id")
    owasp = finding.get("owasp_category")
    if cwe:
        return f"bulwark/{source}/{cwe}"
    if owasp:
        return f"bulwark/{source}/{owasp}"
    return f"bulwark/{source}/finding"


def to_sarif(result: dict, *, version: str = "2.0.0") -> str:
    """Render a standalone-engine result dict to a SARIF JSON string."""
    findings = result.get("findings", [])
    target = result.get("target", "")

    rules: dict[str, dict] = {}
    sarif_results = []

    for f in findings:
        rule_id = _rule_id(f)
        severity = (f.get("severity") or "INFO").upper()
        level, sec_severity = SEVERITY_TO_SARIF.get(severity, ("note", "1.0"))

        # Register the rule once
        if rule_id not in rules:
            help_parts = []
            if f.get("remediation"):
                help_parts.append(f"**Remediation:** {f['remediation']}")
            if f.get("owasp_category"):
                help_parts.append(f"OWASP: {f['owasp_category']}")
            if f.get("references"):
                refs = "\n".join(f"- {r}" for r in f["references"] if r)
                if refs:
                    help_parts.append(f"**References:**\n{refs}")

            rules[rule_id] = {
                "id": rule_id,
                "name": (f.get("title") or rule_id)[:120].replace(" ", ""),
                "shortDescription": {"text": (f.get("title") or "Finding")[:200]},
                "fullDescription": {"text": (f.get("description") or f.get("title") or "")[:1000]},
                "helpUri": (f.get("references") or ["https://github.com/moose11b/bulwark"])[0] or
                           "https://github.com/moose11b/bulwark",
                "help": {"text": "\n\n".join(help_parts) or "See finding details."},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": sec_severity,
                    "tags": _rule_tags(f),
                },
            }

        # Build the result entry
        message = f.get("description") or f.get("title") or "Security finding"
        if f.get("evidence"):
            message += f"\n\nEvidence: {f['evidence']}"

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _target_uri(target)},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "severity": severity,
                "source": f.get("source"),
                "cve_id": f.get("cve_id"),
                "cvss_score": f.get("cvss_score"),
                "epss_score": f.get("epss_score"),
                "in_kev": f.get("is_in_kev", False),
                "killchain_phase": f.get("killchain_phase"),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Bulwark",
                    "informationUri": "https://github.com/moose11b/bulwark",
                    "version": version,
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
            "properties": {
                "target": target,
                "profile": result.get("profile"),
                "scanned_at": result.get("completed_at"),
            },
        }],
    }
    return json.dumps(sarif, indent=2)


def _rule_tags(finding: dict) -> list[str]:
    tags = ["security"]
    if finding.get("owasp_category"):
        tags.append(f"owasp-{finding['owasp_category'].lower()}")
    if finding.get("cwe_id"):
        tags.append(finding["cwe_id"].lower())
    if finding.get("is_in_kev"):
        tags.append("cisa-kev")
    return tags


def _target_uri(target: str) -> str:
    """SARIF needs a location URI; we use the target as a logical location."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}/"
    return target
