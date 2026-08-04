"""
Analysis services: OWASP Top 10, Kill Chain, and Compliance mapping.
These are pure classification layers — they take raw finding dicts
and return enriched copies. No external calls, no DB access.
"""

# ── OWASP Top 10 (2021) ──────────────────────────────────────────

OWASP_CATEGORIES = {
    "A01": {"name": "Broken Access Control",            "risk": "Critical"},
    "A02": {"name": "Cryptographic Failures",            "risk": "High"},
    "A03": {"name": "Injection",                         "risk": "Critical"},
    "A04": {"name": "Insecure Design",                   "risk": "High"},
    "A05": {"name": "Security Misconfiguration",         "risk": "High"},
    "A06": {"name": "Vulnerable & Outdated Components",  "risk": "High"},
    "A07": {"name": "Auth Failures",                     "risk": "High"},
    "A08": {"name": "Software Integrity Failures",       "risk": "High"},
    "A09": {"name": "Logging & Monitoring Failures",     "risk": "Medium"},
    "A10": {"name": "SSRF",                              "risk": "High"},
}

OWASP_KEYWORDS = {
    "A01": ["access control","idor","traversal","directory listing","admin","privilege","authorization"],
    "A02": ["ssl","tls","certificate","cipher","cleartext","plaintext","hsts","rc4","des","heartbleed","poodle"],
    "A03": ["injection","sql","xss","cross-site","command injection","log4j","shellshock","rce","ssti"],
    "A04": ["default credential","no authentication","unauthenticated","rate limit","insecure design"],
    "A05": ["misconfiguration","header","cors","disclosure","debug","directory","spf","dmarc","dnssec","open port","smb"],
    "A06": ["outdated","vulnerable","version","patch","cve","unpatched","wordpress","drupal","struts"],
    "A07": ["authentication","brute force","weak password","session","token","credential","login","jwt","cookie"],
    "A08": ["integrity","deserialization","supply chain","sri","unsigned"],
    "A09": ["logging","monitoring","audit","error disclosure","stack trace","verbose error"],
    "A10": ["ssrf","server-side request","open redirect","internal","localhost","169.254","metadata"],
}

SOURCE_OWASP = {
    "header_scanner": "A05",
    "dns_scanner":    "A05",
    "ssl_scanner":    "A02",
    "nikto":          "A05",
    "shodan":         "A05",
    "nmap":           "A05",
    "nuclei":         "A06",
    "exposure_scanner": "A05",
}

CVE_OWASP = {
    "CVE-2021-44228": "A03",  # Log4Shell
    "CVE-2014-6271":  "A03",  # Shellshock
    "CVE-2014-0160":  "A02",  # Heartbleed
    "CVE-2014-3566":  "A02",  # POODLE
    "CVE-2017-0144":  "A06",  # EternalBlue
    "CVE-2021-41773": "A01",  # Apache path traversal
    "CVE-2022-22965": "A03",  # Spring4Shell
}


def classify_vulnerability(finding: dict) -> tuple[str, str]:
    """Return (owasp_category_code, confidence)."""
    cve = (finding.get("cve_id") or "").upper()
    raw = (finding.get("description") or finding.get("title") or "").lower()
    src = (finding.get("source") or "").lower()

    for cve_id, cat in CVE_OWASP.items():
        if cve_id in cve:
            return cat, "high"

    import re
    if re.match(r"CVE-\d{4}-\d+", cve):
        return "A06", "medium"

    scores = {cat: 0 for cat in OWASP_KEYWORDS}
    for cat, keywords in OWASP_KEYWORDS.items():
        for kw in keywords:
            if kw in raw:
                scores[cat] += 1

    best = max(scores, key=lambda c: scores[c])
    if scores[best] > 0:
        return best, "high" if scores[best] >= 2 else "medium"

    if src in SOURCE_OWASP:
        return SOURCE_OWASP[src], "low"

    return "A05", "low"


def build_owasp_report(scan_id: str, findings: list[dict]) -> dict:
    categories = {
        code: {**meta, "code": code, "findings": [], "count": 0, "max_cvss": 0.0}
        for code, meta in OWASP_CATEGORIES.items()
    }

    for f in findings:
        cat_code = f.get("owasp_category") or classify_vulnerability(f)[0]
        if cat_code not in categories:
            cat_code = "A05"
        entry = {
            "id": f.get("id"), "title": f.get("title"),
            "severity": f.get("severity"), "cvss_score": f.get("cvss_score", 0.0),
            "source": f.get("source"), "cve_id": f.get("cve_id"),
        }
        categories[cat_code]["findings"].append(entry)
        categories[cat_code]["count"] += 1
        if entry["cvss_score"] > categories[cat_code]["max_cvss"]:
            categories[cat_code]["max_cvss"] = entry["cvss_score"]

    radar = [
        {"category": code, "name": OWASP_CATEGORIES[code]["name"][:22],
         "count": categories[code]["count"], "full_mark": max(len(findings), 1)}
        for code in OWASP_CATEGORIES
    ]

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "categories_hit": sum(1 for c in categories.values() if c["count"] > 0),
        "categories": list(categories.values()),
        "radar_data": radar,
    }


# ── Kill Chain ───────────────────────────────────────────────────

KILL_CHAIN_PHASES = [
    {"id": "reconnaissance",  "phase": 1, "name": "Reconnaissance",
     "description": "Attacker gathers information about the target.",
     "defender_action": "Minimise public attack surface. Monitor for scanning activity."},
    {"id": "weaponization",   "phase": 2, "name": "Weaponization",
     "description": "Attacker couples exploit with payload.",
     "defender_action": "Track threat intelligence. Understand adversary TTPs."},
    {"id": "delivery",        "phase": 3, "name": "Delivery",
     "description": "Weapon transmitted to target environment.",
     "defender_action": "Patch exposed services. Analyse delivery vectors."},
    {"id": "exploitation",    "phase": 4, "name": "Exploitation",
     "description": "Exploit code triggers on target system.",
     "defender_action": "Patch vulnerabilities. Harden configs. Deploy WAF/IPS."},
    {"id": "installation",    "phase": 5, "name": "Installation",
     "description": "Malware or backdoor installed for persistent access.",
     "defender_action": "Application whitelisting. Audit startup items and scheduled tasks."},
    {"id": "command_control", "phase": 6, "name": "Command & Control",
     "description": "Attacker communicates with implant.",
     "defender_action": "Block C2 traffic. Monitor DNS and outbound connections."},
    {"id": "actions",         "phase": 7, "name": "Actions on Objectives",
     "description": "Attacker achieves goal: exfiltration, destruction, ransomware.",
     "defender_action": "Data loss prevention. Encrypt sensitive data. Immutable backups."},
]

PHASE_KEYWORDS = {
    "reconnaissance":  ["recon","scan","enumeration","disclosure","fingerprint","spf","dmarc","dns","subdomain","zone transfer","server info","version","open port","banner"],
    "weaponization":   ["exploit kit","payload","malware","caa","certificate authority"],
    "delivery":        ["phishing","email","spf","dmarc","smtp","ssl","tls","hsts","cleartext","plaintext","cors","deliver"],
    "exploitation":    ["exploit","rce","remote code","injection","sql","xss","command injection","buffer overflow","heartbleed","eternalblue","log4shell","shellshock","path traversal","idor","auth bypass","ssrf","ssti"],
    "installation":    ["backdoor","persistence","webshell","shell","cron","scheduled task","file upload","write access"],
    "command_control": ["c2","command and control","beacon","dns tunneling","reverse shell","bind shell","remote access","callback"],
    "actions":         ["exfiltration","data theft","ransomware","encrypt","destroy","defacement","lateral movement","privilege escalation","credential dump","database exposed","mongodb","redis","elasticsearch","mysql exposed"],
}

SOURCE_PHASE = {
    "header_scanner":   "delivery",
    "dns_scanner":      "reconnaissance",
    "ssl_scanner":      "delivery",
    "nmap":             "reconnaissance",
    "exposure_scanner": "reconnaissance",
    "nikto":            "exploitation",
    "nuclei":           "exploitation",
    "shodan":           "reconnaissance",
}

CVE_PHASE = {
    "CVE-2021-44228": "exploitation",
    "CVE-2014-6271":  "exploitation",
    "CVE-2014-0160":  "reconnaissance",
    "CVE-2017-0144":  "exploitation",
    "CVE-2014-3566":  "delivery",
    "CVE-2023-46604": "exploitation",
}

SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0, "PASS": 0}


def classify_to_phase(finding: dict) -> tuple[str, str]:
    cve = (finding.get("cve_id") or "").upper()
    raw = ((finding.get("description") or "") + " " + (finding.get("title") or "")).lower()
    src = (finding.get("source") or "").lower()

    for cve_id, phase in CVE_PHASE.items():
        if cve_id in cve:
            return phase, "high"

    scores = {p: 0 for p in PHASE_KEYWORDS}
    for phase, keywords in PHASE_KEYWORDS.items():
        for kw in keywords:
            if kw in raw:
                scores[phase] += 1

    best = max(scores, key=lambda p: scores[p])
    if scores[best] > 0:
        return best, "high" if scores[best] >= 2 else "medium"

    if src in SOURCE_PHASE:
        return SOURCE_PHASE[src], "low"

    return "reconnaissance", "low"


def build_killchain_report(scan_id: str, findings: list[dict]) -> dict:
    phase_data = {p["id"]: {**p, "findings": [], "count": 0, "heat": 0}
                  for p in KILL_CHAIN_PHASES}

    for f in findings:
        phase_id = f.get("killchain_phase") or classify_to_phase(f)[0]
        if phase_id not in phase_data:
            phase_id = "reconnaissance"
        weight = SEV_WEIGHT.get((f.get("severity") or "INFO").upper(), 0)
        phase_data[phase_id]["findings"].append({
            "id": f.get("id"), "title": f.get("title"),
            "severity": f.get("severity"), "cvss_score": f.get("cvss_score", 0.0),
            "source": f.get("source"),
        })
        phase_data[phase_id]["count"] += 1
        phase_data[phase_id]["heat"] += max(weight, 1)

    max_heat = max((p["heat"] for p in phase_data.values()), default=1) or 1
    for p in phase_data.values():
        p["heat_pct"] = round(p["heat"] / max_heat * 100)

    phases = [phase_data[p["id"]] for p in KILL_CHAIN_PHASES]
    highest = max((p for p in phases if p["count"] > 0), key=lambda p: p["phase"], default=None)

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "exposed_phases": sum(1 for p in phases if p["count"] > 0),
        "highest_phase": highest["phase"] if highest else 0,
        "highest_phase_name": highest["name"] if highest else "None",
        "phases": phases,
        "bar_data": [{"phase": p["name"][:16], "count": p["count"], "heat": p["heat_pct"]}
                     for p in phases],
    }


# ── Compliance mapper ────────────────────────────────────────────

COMPLIANCE_DB = {}  # retained for import compat; see services/compliance.py


def map_compliance(finding: dict) -> dict:
    """Delegate to the comprehensive compliance module.

    Returns relevant control IDs across PCI-DSS, ISO 27001:2022, NIST CSF 2.0,
    and CIS Controls v8. See services/compliance.py for the full mapping and
    the important control-mapping disclaimer.
    """
    from app.services.compliance import map_compliance as _map
    return _map(finding)
