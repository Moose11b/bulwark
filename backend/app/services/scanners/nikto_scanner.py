import asyncio
import json
import re
import subprocess
import tempfile
import os
import structlog

from app.services.scanners.availability import fallback, empty_or_demo

logger = structlog.get_logger()

# Map Nikto OSVDB/finding patterns to OWASP and kill chain
NIKTO_OWASP_MAP = {
    "sql": ("A03", "exploitation", "T1190"),
    "xss": ("A03", "exploitation", "T1059"),
    "injection": ("A03", "exploitation", "T1190"),
    "default": ("A05", "reconnaissance", "T1595"),
    "backup": ("A05", "reconnaissance", "T1083"),
    "config": ("A05", "reconnaissance", "T1083"),
    "password": ("A07", "exploitation", "T1110"),
    "authentication": ("A07", "exploitation", "T1110"),
    "directory": ("A05", "reconnaissance", "T1083"),
    "disclosure": ("A05", "reconnaissance", "T1592"),
    "version": ("A06", "reconnaissance", "T1592"),
    "outdated": ("A06", "reconnaissance", "T1592"),
    "php": ("A06", "reconnaissance", "T1592"),
    "apache": ("A06", "reconnaissance", "T1592"),
    "nginx": ("A06", "reconnaissance", "T1592"),
    "cgi": ("A06", "exploitation", "T1190"),
    "upload": ("A01", "exploitation", "T1190"),
    "csrf": ("A03", "exploitation", "T1185"),
    "cookie": ("A07", "exploitation", "T1185"),
    "ssl": ("A02", "delivery", "T1040"),
    "tls": ("A02", "delivery", "T1040"),
    "header": ("A05", "delivery", "T1557"),
}

SEVERITY_PATTERNS = {
    "CRITICAL": ["remote code", "rce", "command injection", "sql injection", "arbitrary code"],
    "HIGH":     ["authentication bypass", "directory traversal", "path traversal", "arbitrary file",
                 "file inclusion", "default credentials", "credentials", "admin"],
    "MEDIUM":   ["disclosure", "information", "cross-site", "xss", "csrf", "redirect",
                 "outdated", "version", "backup"],
    "LOW":      ["directory index", "directory listing", "robots.txt", "sitemap",
                 "cookie", "header", "cache"],
}


def _classify_severity(msg: str) -> str:
    msg_lower = msg.lower()
    for sev, patterns in SEVERITY_PATTERNS.items():
        if any(p in msg_lower for p in patterns):
            return sev
    return "INFO"


def _classify_owasp(msg: str) -> tuple[str, str, str]:
    msg_lower = msg.lower()
    for keyword, (owasp, phase, mitre) in NIKTO_OWASP_MAP.items():
        if keyword in msg_lower:
            return owasp, phase, mitre
    return "A05", "reconnaissance", "T1595"


# Lines Nikto prefixes with '+' that describe the run rather than the target.
# Without this filter the scan's own end timestamp and request tally were
# reported as security findings.
_NIKTO_NON_FINDING = re.compile(
    r"^(?:"
    r"Target\s+(?:IP|Hostname|Port)"
    r"|Start\s+Time|End\s+Time"
    r"|\d[\d,]*\s+requests?:"           # "8724 requests: 0 error(s) and ..."
    r"|\d+\s+host\(s\)\s+tested"
    r"|No CGI Directories found"
    r"|Nikto v"
    r")",
    re.IGNORECASE,
)

# Below this length a '+' line is a fragment rather than a described issue.
_MIN_FINDING_LENGTH = 20


def _parse_nikto_output(raw: str, target: str) -> list[dict]:
    """Turn Nikto's text report into findings.

    Only '+ ' lines carry results; everything else is banner or separator.
    Metadata lines are filtered explicitly rather than by pattern-guessing, so
    a new Nikto version adding a summary line cannot become a fake finding.
    """
    findings = []

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue

        content = line[2:].strip()
        if not content or _NIKTO_NON_FINDING.match(content):
            continue

        if content.startswith("OSVDB"):
            # Format: OSVDB-XXXXX: /path: description
            ref, _, rest = content.partition(":")
            ref = ref.strip()
            rest = rest.strip()

            path_match = re.match(r'(/[^\s:]*)?:?\s*(.*)', rest)
            path = (path_match.group(1) or "") if path_match else ""
            desc = (path_match.group(2) or rest) if path_match else rest
            if not desc:
                continue

            findings.append(_nikto_finding(
                desc, target,
                evidence=f"{ref} found at {target}{path}" if path else f"{ref} on {target}",
                references=[f"https://www.osvdb.org/{ref.replace('OSVDB-', '')}"],
            ))

        elif len(content) > _MIN_FINDING_LENGTH:
            findings.append(_nikto_finding(
                content, target, evidence=f"Nikto scan of {target}",
            ))

    return findings


def _nikto_finding(desc: str, target: str, *, evidence: str,
                   references: list[str] | None = None) -> dict:
    owasp, phase, mitre = _classify_owasp(desc)
    return {
        "title": f"Nikto: {desc[:120]}",
        "source": "nikto",
        "severity": _classify_severity(desc),
        "cwe_id": None,
        "owasp_category": owasp,
        "killchain_phase": phase,
        "mitre_technique_id": mitre,
        "description": desc,
        "evidence": evidence,
        "remediation": _remediation_hint(desc),
        "references": references or [],
    }


def _remediation_hint(desc: str) -> str:
    d = desc.lower()
    if "default" in d and ("credential" in d or "password" in d):
        return "Change all default credentials immediately. Enforce strong password policy."
    if "directory" in d and ("listing" in d or "index" in d):
        return "Disable directory listing in web server config (Options -Indexes / autoindex off)."
    if "backup" in d:
        return "Remove backup files from the web root. Store backups outside the document root."
    if "disclosure" in d or "version" in d:
        return "Remove or suppress version information from HTTP headers and error pages."
    if "outdated" in d or "old" in d:
        return "Update the affected software to the latest stable version and apply security patches."
    if "sql" in d:
        return "Use parameterised queries / prepared statements. Never interpolate user input into SQL."
    if "xss" in d:
        return "Encode all user-supplied output. Implement a strict Content-Security-Policy."
    if "cookie" in d:
        return "Set HttpOnly, Secure, and SameSite=Strict attributes on all session cookies."
    if "ssl" in d or "tls" in d:
        return "Upgrade to TLS 1.2+ with strong cipher suites. Disable deprecated protocols."
    if "header" in d:
        return "Add missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)."
    return "Review the finding and apply appropriate hardening based on the affected component."


class NiktoScanner:
    """Async wrapper around the Nikto CLI web vulnerability scanner."""

    async def scan(self, target: str, progress_cb=None, pinned_ip: str | None = None,
                   allow_private: bool = False, port: int | None = None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._run, target, progress_cb, pinned_ip, allow_private, port
        )

    def _run(self, target: str, progress_cb=None, pinned_ip: str | None = None,
             allow_private: bool = False, port: int | None = None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]

        # Pre-launch SSRF guard: Nikto does its own DNS resolution, so we
        # re-verify the host is still public right before launching to
        # minimise the DNS-rebind window. Skipped only for trusted local scans.
        if not allow_private:
            from app.core.pinned_connection import assert_still_public
            if not assert_still_public(hostname):
                logger.warning("nikto.ssrf_guard_blocked", target=hostname)
                return []

        # Determine scheme. A non-443 explicit port is treated as plain HTTP,
        # matching how these services are usually exposed.
        if port:
            scheme = "https" if port == 443 else "http"
            scan_url = f"{scheme}://{hostname}:{port}"
        else:
            scheme = "https" if not target.startswith("http://") else "http"
            scan_url = f"{scheme}://{hostname}"

        if progress_cb:
            progress_cb(10, f"Starting Nikto scan against {hostname}...")

        # Check nikto is available
        try:
            subprocess.run(["nikto", "-Version"], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("nikto.not_found", target=hostname)
            return self._unavailable(hostname, "The nikto binary is not installed.")

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    "nikto",
                    "-h", scan_url,
                    "-nointeractive",
                    "-Tuning", "1234578",  # Skip slow/dangerous tests
                    "-timeout", "10",
                    "-maxtime", "300",
                    "-output", tmp_path,
                    "-Format", "txt",
                ],
                capture_output=True,
                text=True,
                timeout=360,
            )

            if progress_cb:
                progress_cb(70, "Parsing Nikto results...")

            raw = ""
            if os.path.exists(tmp_path):
                with open(tmp_path) as f:
                    raw = f.read()

            # Also parse stdout
            raw += "\n" + result.stdout

            findings = _parse_nikto_output(raw, scan_url)

            if progress_cb:
                progress_cb(100, f"Nikto complete — {len(findings)} findings")

            logger.info("nikto.complete", target=hostname, findings=len(findings))
            # A clean Nikto run genuinely finding nothing is a real result.
            return empty_or_demo(findings, "nikto",
                                 lambda: self._demo_results(hostname))

        except subprocess.TimeoutExpired:
            logger.warning("nikto.timeout", target=hostname)
            return self._unavailable(
                hostname, "The nikto scan exceeded its time limit and was stopped."
            )
        except Exception as e:
            logger.error("nikto.error", target=hostname, error=str(e))
            return self._unavailable(hostname, f"The nikto scan failed: {e}.")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _unavailable(self, hostname: str, reason: str) -> list[dict]:
        return fallback(
            "Nikto", "nikto", reason,
            "Install nikto in the scanner image to enable web server "
            "misconfiguration checks.",
            lambda: self._demo_results(hostname),
        )

    def _demo_results(self, hostname: str) -> list[dict]:
        logger.info("nikto.using_demo_results", target=hostname)
        return [
            {
                "title": "Nikto: Web server exposes version information",
                "source": "nikto", "severity": "LOW",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1592",
                "description": "The web server discloses its version in the Server HTTP header, "
                               "which assists attackers in identifying known vulnerabilities.",
                "evidence": f"Server header present on {hostname}",
                "remediation": "Remove or obfuscate the Server header in web server configuration.",
                "references": [],
            },
            {
                "title": "Nikto: Missing anti-clickjacking header",
                "source": "nikto", "severity": "MEDIUM",
                "cwe_id": "CWE-1021", "owasp_category": "A05",
                "killchain_phase": "exploitation", "mitre_technique_id": "T1185",
                "description": "The site does not set an X-Frame-Options or CSP frame-ancestors directive, "
                               "making it vulnerable to clickjacking attacks.",
                "evidence": f"No X-Frame-Options header on {hostname}",
                "remediation": "Add: X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
                "references": [],
            },
            {
                "title": "Nikto: Allowed HTTP methods include TRACE",
                "source": "nikto", "severity": "LOW",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1592",
                "description": "The TRACE HTTP method is enabled. This can be used in "
                               "cross-site tracing (XST) attacks to steal cookies.",
                "evidence": f"OPTIONS response on {hostname} includes TRACE",
                "remediation": "Disable the TRACE method in your web server configuration.",
                "references": ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            },
            {
                "title": "Nikto: /admin/ directory accessible",
                "source": "nikto", "severity": "MEDIUM",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1083",
                "description": "An administrative directory was found accessible. "
                               "This could expose management interfaces to unauthorised users.",
                "evidence": f"HTTP 200/302 response from {hostname}/admin/",
                "remediation": "Restrict access to /admin/ using IP allowlisting, authentication, or relocate off the web root.",
                "references": [],
            },
        ]
