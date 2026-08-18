#!/usr/bin/env python3
"""
Benchmark comparator.

Normalises the output of Bulwark and OWASP ZAP into one finding shape, then:
  1. scores each tool against a target's ground-truth vulnerability list
     (detection rate + false positives on known-good endpoints), and
  2. tabulates raw output side by side (by severity and OWASP category).

Design principle: the honest headline number is **detection rate against
ground truth**, not raw finding count. A tool reporting 200 findings is not
"better" than one reporting 20 — it may just be noisier. Raw counts are shown
for context and always labelled as such.

Usage:
    python compare.py \
        --target vulnapi \
        --bulwark bulwark.json \
        --zap zap.json \
        --ground-truth targets/vulnapi/ground_truth.yaml \
        --out-md comparison.md --out-json comparison.json

Either tool's file may be omitted (e.g. a Bulwark-only run); the report simply
shows what it has.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ZAP riskcode → severity. ZAP has no CRITICAL tier.
_ZAP_RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

# Minimal CWE → OWASP-2021 map for the CWEs these tools emit most. Used to give
# ZAP findings an OWASP category comparable to Bulwark's. Best-effort: an
# unmapped CWE is left uncategorised rather than guessed.
_CWE_OWASP = {
    "79": "A03", "89": "A03", "77": "A03", "78": "A03", "94": "A03", "917": "A03",
    "22": "A01", "639": "A01", "284": "A01", "552": "A01", "548": "A01",
    "200": "A05", "16": "A05", "693": "A05", "525": "A05", "1021": "A05",
    "319": "A02", "326": "A02", "327": "A02", "311": "A02",
    "306": "A07", "287": "A07", "384": "A07", "614": "A07", "1004": "A07",
    "937": "A06", "1035": "A06", "829": "A06",
    "209": "A05", "215": "A05",
}


@dataclass
class Finding:
    tool: str
    name: str
    severity: str
    owasp: str          # "A0x" or ""
    cwe: str            # bare number or ""
    endpoint: str       # best-effort, "" if not applicable


# ── Normalisers ──────────────────────────────────────────────────

def normalize_bulwark(result: dict) -> list[Finding]:
    """Bulwark standalone-engine JSON → findings."""
    out = []
    for f in result.get("findings", []):
        if f.get("suppressed"):
            continue
        out.append(Finding(
            tool="bulwark",
            name=str(f.get("title") or ""),
            severity=(f.get("severity") or "INFO").upper(),
            owasp=str(f.get("owasp_category") or ""),
            cwe=_cwe_number(f.get("cwe_id")),
            endpoint=_endpoint_from_title(str(f.get("title") or "")),
        ))
    return out


def normalize_zap(report: dict) -> list[Finding]:
    """ZAP baseline JSON report (`zap-baseline.py -J`) → findings.

    ZAP groups instances under one alert; we keep the alert as a single finding
    (the benchmark scores issues, not instance counts).
    """
    out = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            cwe = str(alert.get("cweid") or "").strip()
            if cwe in ("", "-1"):
                cwe = ""
            owasp = _owasp_from_zap(alert)
            name = str(alert.get("name") or alert.get("alert") or "")
            endpoint = _endpoint_from_zap(alert)
            out.append(Finding(
                tool="zap",
                name=name,
                severity=_ZAP_RISK.get(str(alert.get("riskcode", "0")), "INFO"),
                owasp=owasp,
                cwe=cwe,
                endpoint=endpoint,
            ))
    return out


def _owasp_from_zap(alert: dict) -> str:
    # Newer ZAP tags OWASP directly; fall back to the CWE map.
    tags = alert.get("tags") or {}
    if isinstance(tags, dict):
        for key in tags:
            k = str(key).upper().replace("_", "")
            # e.g. "OWASP_2021_A01" or "OWASP2021-A03"
            for i in range(1, 11):
                if f"A{i:02d}" in k and "2021" in k:
                    return f"A{i:02d}"
    return _CWE_OWASP.get(str(alert.get("cweid") or "").strip(), "")


def _endpoint_from_zap(alert: dict) -> str:
    inst = alert.get("instances") or []
    if inst and isinstance(inst, list) and isinstance(inst[0], dict):
        uri = str(inst[0].get("uri") or "")
        method = str(inst[0].get("method") or "").upper()
        path = uri.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1] if "/" in path else path
        return f"{method} {path}".strip()
    return ""


def _cwe_number(cwe_id) -> str:
    if not cwe_id:
        return ""
    s = str(cwe_id).upper().replace("CWE-", "").strip()
    return s if s.isdigit() else ""


def _endpoint_from_title(title: str) -> str:
    # Bulwark's API findings are titled e.g. "Authentication not enforced: GET /x".
    if ":" in title:
        tail = title.split(":", 1)[1].strip()
        parts = tail.split()
        if parts and parts[0] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return tail
    return ""


# ── Ground-truth scoring ─────────────────────────────────────────

def _text_of(f: Finding) -> str:
    return f"{f.name} {f.endpoint}".lower()


def _matches_planted(f: Finding, planted: dict) -> bool:
    """Credit a tool for finding the *issue*, however it words or categorises it.

    A specific keyword ("object-level", "/api/users", "content-security-policy")
    is the reliable identity signal — far more so than the OWASP category, which
    tools genuinely disagree on (Bulwark files CSP under A03, ZAP tags it A05).
    So a keyword hit alone is a match. OWASP category is only a fallback for
    planted entries that specify no keywords.
    """
    m = planted.get("match", {})
    kw = [k.lower() for k in (m.get("keywords") or [])]
    if kw:
        return any(k in _text_of(f) for k in kw)
    return f.owasp in (m.get("owasp") or [])


def _is_false_positive(f: Finding, control: dict) -> bool:
    kws = [k.lower() for k in (control.get("false_positive_keywords") or [])]
    ep_ok = any(k in _text_of(f) for k in kws)
    owasp_bad = f.owasp in (control.get("false_positive_owasp") or [])
    return ep_ok and owasp_bad


def score_against_ground_truth(findings: list[Finding], ground_truth: dict) -> dict:
    planted = ground_truth.get("planted", [])
    controls = ground_truth.get("controls", [])

    detected, missed = [], []
    for p in planted:
        hit = next((f for f in findings if _matches_planted(f, p)), None)
        (detected if hit else missed).append({
            "id": p["id"], "title": p["title"], "owasp": p.get("owasp"),
            "severity": p.get("severity"),
            "matched_by": hit.name if hit else None,
        })

    false_positives = []
    for f in findings:
        for c in controls:
            if _is_false_positive(f, c):
                false_positives.append({"finding": f.name, "endpoint": f.endpoint,
                                        "control": c["id"]})

    matched_names = {d["matched_by"] for d in detected if d["matched_by"]}
    additional = [
        {"name": f.name, "severity": f.severity, "owasp": f.owasp}
        for f in findings
        if f.name not in matched_names
        and not any(_is_false_positive(f, c) for c in controls)
    ]

    n = len(planted)
    return {
        "planted_total": n,
        "detected": len(detected),
        "detection_rate": round(len(detected) / n, 3) if n else None,
        "detected_items": detected,
        "missed_items": missed,
        "false_positives": false_positives,
        "additional_findings": additional,
    }


# ── Tabulation ───────────────────────────────────────────────────

def _counts_by(findings: list[Finding], attr: str, keys: list[str]) -> dict:
    counts = {k: 0 for k in keys}
    for f in findings:
        v = getattr(f, attr)
        if v in counts:
            counts[v] += 1
        else:
            counts.setdefault(v or "uncategorised", 0)
            counts[v or "uncategorised"] += 1
    return counts


def build_report(target: str, bulwark: list[Finding] | None,
                 zap: list[Finding] | None, ground_truth: dict | None,
                 durations: dict | None = None) -> dict:
    report = {"target": target, "tools": {}, "durations": durations or {}}

    for name, fs in (("bulwark", bulwark), ("zap", zap)):
        if fs is None:
            continue
        entry = {
            "total": len(fs),
            "by_severity": _counts_by(fs, "severity", SEVERITIES),
        }
        if ground_truth:
            entry["ground_truth"] = score_against_ground_truth(fs, ground_truth)
        report["tools"][name] = entry

    return report


# ── Markdown rendering ───────────────────────────────────────────

def render_markdown(report: dict) -> str:
    tools = report["tools"]
    L = [f"## Benchmark: `{report['target']}`", ""]

    if report.get("durations"):
        d = "  ·  ".join(f"{k}: {v}s" for k, v in report["durations"].items())
        L.append(f"_Scan duration — {d}_")
        L.append("")

    # Ground-truth detection is the headline.
    gt_tools = {t: e for t, e in tools.items() if "ground_truth" in e}
    if gt_tools:
        L.append("### Detection rate vs. ground truth")
        L.append("")
        L.append("| Tool | Detected | Detection rate | False positives |")
        L.append("|---|---|---|---|")
        for t, e in gt_tools.items():
            g = e["ground_truth"]
            rate = f"{g['detection_rate'] * 100:.0f}%" if g["detection_rate"] is not None else "—"
            L.append(f"| {t} | {g['detected']}/{g['planted_total']} | "
                     f"**{rate}** | {len(g['false_positives'])} |")
        L.append("")

        # Per-vuln breakdown (which planted issue each tool caught).
        any_gt = next(iter(gt_tools.values()))["ground_truth"]
        planted_ids = [d["id"] for d in any_gt["detected_items"] + any_gt["missed_items"]]
        L.append("### Which planted vulnerabilities were caught")
        L.append("")
        header = "| Planted vulnerability | OWASP | " + " | ".join(gt_tools) + " |"
        L.append(header)
        L.append("|---" * (2 + len(gt_tools)) + "|")
        # Build a lookup per tool of detected ids.
        detected_ids = {t: {d["id"] for d in e["ground_truth"]["detected_items"]}
                        for t, e in gt_tools.items()}
        titles = {d["id"]: (d["title"], d["owasp"])
                  for d in any_gt["detected_items"] + any_gt["missed_items"]}
        for pid in planted_ids:
            title, owasp = titles[pid]
            cells = ["✅" if pid in detected_ids[t] else "❌" for t in gt_tools]
            L.append(f"| {title} | {owasp} | " + " | ".join(cells) + " |")
        L.append("")

    # Raw output, clearly labelled as context not score.
    L.append("### Raw output by severity (context, not a score)")
    L.append("")
    L.append("| Severity | " + " | ".join(tools) + " |")
    L.append("|---" * (1 + len(tools)) + "|")
    for sev in SEVERITIES:
        cells = [str(e["by_severity"].get(sev, 0)) for e in tools.values()]
        L.append(f"| {sev.title()} | " + " | ".join(cells) + " |")
    total_cells = [str(e["total"]) for e in tools.values()]
    L.append(f"| **Total** | " + " | ".join(f"**{c}**" for c in total_cells) + " |")
    L.append("")

    # Honest caveat, always printed.
    L.append("> Raw counts measure verbosity, not quality — a higher number is "
             "not automatically better. The detection-rate table above, scored "
             "against a known ground-truth list, is the meaningful comparison. "
             "See [benchmarks/README.md](README.md) for methodology and caveats.")
    L.append("")
    return "\n".join(L)


# ── CLI ──────────────────────────────────────────────────────────

def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_yaml(path):
    import yaml
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare Bulwark and ZAP output.")
    ap.add_argument("--target", required=True)
    ap.add_argument("--bulwark", help="Bulwark result JSON")
    ap.add_argument("--zap", help="ZAP baseline JSON report")
    ap.add_argument("--ground-truth", help="ground_truth.yaml for the target")
    ap.add_argument("--bulwark-seconds", type=float)
    ap.add_argument("--zap-seconds", type=float)
    ap.add_argument("--out-md")
    ap.add_argument("--out-json")
    args = ap.parse_args(argv)

    bulwark = normalize_bulwark(_load_json(args.bulwark)) if args.bulwark else None
    zap = normalize_zap(_load_json(args.zap)) if args.zap else None
    gt = _load_yaml(args.ground_truth) if args.ground_truth else None

    durations = {}
    if args.bulwark_seconds is not None:
        durations["bulwark"] = args.bulwark_seconds
    if args.zap_seconds is not None:
        durations["zap"] = args.zap_seconds

    report = build_report(args.target, bulwark, zap, gt, durations)
    md = render_markdown(report)

    if args.out_json:
        with open(args.out_json, "w") as fh:
            json.dump(report, fh, indent=2)
    if args.out_md:
        with open(args.out_md, "w") as fh:
            fh.write(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
