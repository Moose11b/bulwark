"""
Scan importers — turn scanner output into Siege Tower findings.

Supports two input shapes, auto-detected:
  * Bulwark native result JSON  ({"target", "findings": [...], ...})
  * SARIF 2.1.0                 ({"runs": [{"results": [...], ...}]})

SARIF support means the same path also ingests other scanners that emit SARIF
(many do), so Bulwark is the first-class case but not the only one. Pure parsing
— no network, no execution.
"""
from __future__ import annotations

_SEV = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "informational", "INFORMATIONAL": "informational",
    "ERROR": "high", "WARNING": "medium", "NOTE": "low", "NONE": "informational",
}
_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "informational"}


def _norm_cwe(cwe) -> str | None:
    if cwe is None or cwe == "":
        return None
    s = str(cwe)
    if s.upper().startswith("CWE-"):
        return s.upper()
    return f"CWE-{s}"


def _clip(s, n=20000):
    return (s[:n] if isinstance(s, str) else s) or None


def _bulwark_finding(f: dict, target: str | None) -> dict:
    sev = _SEV.get((f.get("severity") or "").upper())
    refs = [r for r in (f.get("references") or []) if r]
    if f.get("cve_id"):
        refs.append(str(f["cve_id"]))
    desc = f.get("description") or ""
    if f.get("evidence"):
        desc = (desc + f"\n\nEvidence: {f['evidence']}").strip()
    tags = [t for t in ["imported", "bulwark", f.get("source"), f.get("owasp_category")] if t]
    return {
        "title": (f.get("title") or "Imported finding")[:300],
        "severity": sev,
        "cvss_score": f.get("cvss_score"),
        "description": _clip(desc),
        "remediation": _clip(f.get("remediation")),
        "affected_assets": [target] if target else [],
        "references": refs[:200],
        "cwe": _norm_cwe(f.get("cwe_id")),
        "tags": tags[:100],
        "status": "open",
    }


def _parse_bulwark(data: dict) -> list[dict]:
    target = data.get("target")
    return [_bulwark_finding(f, target) for f in (data.get("findings") or [])]


def _parse_sarif(data: dict) -> list[dict]:
    out: list[dict] = []
    for run in (data.get("runs") or []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name") or "scanner"
        rules = {r.get("id"): r for r in (driver.get("rules") or [])}
        target = (run.get("properties") or {}).get("target")
        for res in (run.get("results") or []):
            rid = res.get("ruleId")
            rule = rules.get(rid, {})
            props = res.get("properties") or {}
            sev = _SEV.get((props.get("severity") or "").upper()) \
                or _SARIF_LEVEL.get((res.get("level") or "note").lower(), "informational")
            cvss = props.get("cvss_score")
            if cvss is None:
                secsev = (rule.get("properties") or {}).get("security-severity")
                try:
                    cvss = float(secsev) if secsev is not None else None
                except (TypeError, ValueError):
                    cvss = None
            assets = []
            for loc in (res.get("locations") or []):
                uri = (((loc.get("physicalLocation") or {}).get("artifactLocation")) or {}).get("uri")
                if uri:
                    assets.append(uri)
            if not assets and target:
                assets = [target]
            title = ((rule.get("shortDescription") or {}).get("text")
                     or (res.get("message") or {}).get("text") or rid or "Finding")
            desc = ((res.get("message") or {}).get("text")
                    or (rule.get("fullDescription") or {}).get("text"))
            refs = []
            if rule.get("helpUri"):
                refs.append(rule["helpUri"])
            if props.get("cve_id"):
                refs.append(str(props["cve_id"]))
            tags = [t for t in ["imported", tool_name.lower(), props.get("source")] if t]
            out.append({
                "title": str(title)[:300],
                "severity": sev,
                "cvss_score": cvss,
                "description": _clip(desc),
                "remediation": _clip((rule.get("help") or {}).get("text")),
                "affected_assets": assets,
                "references": refs[:200],
                "cwe": None,
                "tags": tags[:100],
                "status": "open",
            })
    return out


def parse(data) -> tuple[str, list[dict]]:
    """Detect the format and return (source_label, findings). Raises ValueError
    on an unrecognized shape."""
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    if isinstance(data.get("runs"), list):
        return "sarif", _dedupe(_parse_sarif(data))
    if isinstance(data.get("findings"), list):
        return "bulwark", _dedupe(_parse_bulwark(data))
    raise ValueError("Unrecognized scan format (expected Bulwark JSON or SARIF)")


def _dedupe(findings: list[dict]) -> list[dict]:
    """Drop exact duplicates (same title + first asset) within one import."""
    seen = set()
    out = []
    for f in findings:
        key = (f.get("title", "").lower(), tuple(f.get("affected_assets") or [])[:1])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
