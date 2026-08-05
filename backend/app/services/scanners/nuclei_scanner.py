import asyncio
import json
import re
import subprocess
import structlog

from app.services.scanners.availability import fallback, empty_or_demo

logger = structlog.get_logger()

# Nuclei severity → Bulwark severity
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}

# Nuclei tag → OWASP category
TAG_OWASP = {
    "sqli":          "A03",
    "xss":           "A03",
    "injection":     "A03",
    "lfi":           "A01",
    "rfi":           "A01",
    "traversal":     "A01",
    "idor":          "A01",
    "ssrf":          "A10",
    "rce":           "A03",
    "ssti":          "A03",
    "auth":          "A07",
    "auth-bypass":   "A07",
    "default-login": "A07",
    "misconfig":     "A05",
    "exposure":      "A05",
    "info-disclosure":"A05",
    "cve":           "A06",
    "cors":          "A05",
    "jwt":           "A07",
    "ssl":           "A02",
    "tls":           "A02",
    "crypto":        "A02",
    "upload":        "A04",
}

TAG_PHASE = {
    "sqli":          "exploitation",
    "xss":           "exploitation",
    "rce":           "exploitation",
    "ssrf":          "exploitation",
    "lfi":           "exploitation",
    "rfi":           "exploitation",
    "ssti":          "exploitation",
    "auth-bypass":   "exploitation",
    "default-login": "exploitation",
    "idor":          "exploitation",
    "traversal":     "exploitation",
    "misconfig":     "reconnaissance",
    "exposure":      "reconnaissance",
    "info-disclosure":"reconnaissance",
    "cve":           "exploitation",
    "ssl":           "delivery",
    "tls":           "delivery",
    "cors":          "delivery",
    "upload":        "installation",
}

TAG_MITRE = {
    "sqli":          "T1190",
    "xss":           "T1059",
    "rce":           "T1190",
    "ssrf":          "T1190",
    "lfi":           "T1083",
    "rfi":           "T1190",
    "auth-bypass":   "T1190",
    "default-login": "T1110",
    "misconfig":     "T1595",
    "exposure":      "T1083",
    "cve":           "T1190",
    "ssl":           "T1040",
    "cors":          "T1557",
}


def _map_tags(tags: list[str]) -> tuple[str, str, str]:
    """Return (owasp, killchain_phase, mitre_id) from Nuclei tags."""
    for tag in tags:
        t = tag.lower().strip()
        if t in TAG_OWASP:
            return (
                TAG_OWASP[t],
                TAG_PHASE.get(t, "reconnaissance"),
                TAG_MITRE.get(t, "T1595"),
            )
    return "A05", "reconnaissance", "T1595"


def _extract_cve(template_id: str, tags: list[str]) -> str | None:
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    for source in [template_id] + tags:
        m = cve_pattern.search(source)
        if m:
            return m.group(0).upper()
    return None


def _parse_nuclei_jsonl(output: str, target: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Nuclei JSONL format fields
        template_id   = item.get("template-id", "")
        template_name = item.get("info", {}).get("name", template_id)
        severity      = item.get("info", {}).get("severity", "info")
        description   = item.get("info", {}).get("description", "")
        remediation   = item.get("info", {}).get("remediation", "")
        references    = item.get("info", {}).get("reference", []) or []
        tags_raw      = item.get("info", {}).get("tags", "")
        tags          = [t.strip() for t in tags_raw.split(",")] if isinstance(tags_raw, str) else tags_raw
        matched_at    = item.get("matched-at", target)
        matcher_name  = item.get("matcher-name", "")
        extracted     = item.get("extracted-results", [])
        curl_cmd      = item.get("curl-command", "")
        cwe_id        = None

        # CWE from classification
        classification = item.get("info", {}).get("classification", {})
        cwes = classification.get("cwe-id", [])
        if cwes:
            cwe_id = cwes[0] if isinstance(cwes, list) else cwes

        # Written out rather than chained: a conditional expression binds
        # looser than `or`, so the previous one-liner evaluated as
        #   (extracted or classification_cve) if classification_cve else None
        # which threw away a CVE found in the template id whenever the
        # classification block had none — the common case for CVE templates.
        # The finding was then stored with no CVE and never enriched.
        classification_cve = classification.get("cve-id")
        if isinstance(classification_cve, list):
            classification_cve = classification_cve[0] if classification_cve else None

        cve_id = _extract_cve(template_id, tags) or classification_cve

        owasp, phase, mitre = _map_tags(tags)

        # Build evidence string
        evidence_parts = [f"Matched at: {matched_at}"]
        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:3])}")

        findings.append({
            "title": f"Nuclei: {template_name}",
            "source": "nuclei",
            "severity": SEVERITY_MAP.get(severity.lower(), "INFO"),
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "owasp_category": owasp,
            "killchain_phase": phase,
            "mitre_technique_id": mitre,
            "description": description or f"Nuclei template {template_id} matched.",
            "evidence": " | ".join(evidence_parts),
            "remediation": remediation or "Review the Nuclei template documentation for remediation guidance.",
            "references": references if isinstance(references, list) else [references],
            "raw_output": curl_cmd[:500] if curl_cmd else "",
        })

    return findings


class NucleiScanner:
    """Async wrapper around the Nuclei template-based vulnerability scanner."""

    # Nuclei template tags to run — focused set for security assessment
    DEFAULT_TAGS = ",".join([
        "cve",
        "misconfig",
        "exposure",
        "default-login",
        "xss",
        "sqli",
        "ssrf",
        "lfi",
        "rce",
        "auth-bypass",
        "info-disclosure",
        "ssl",
        "cors",
    ])

    async def scan(self, target: str, progress_cb=None, pinned_ip: str | None = None,
                   allow_private: bool = False, port: int | None = None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._run, target, progress_cb, pinned_ip, allow_private, port
        )

    def _run(self, target: str, progress_cb=None, pinned_ip: str | None = None,
             allow_private: bool = False, port: int | None = None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]

        # Pre-launch SSRF guard: Nuclei resolves DNS itself, so re-verify the
        # host is still public right before launching to minimise the
        # DNS-rebind window. Skipped only for trusted local scans.
        if not allow_private:
            from app.core.pinned_connection import assert_still_public
            if not assert_still_public(hostname):
                logger.warning("nuclei.ssrf_guard_blocked", target=hostname)
                return []
        if port:
            scheme = "https" if port == 443 else "http"
            scan_url = f"{scheme}://{hostname}:{port}"
        else:
            scheme = "http" if target.startswith("http://") else "https"
            scan_url = f"{scheme}://{hostname}"

        if progress_cb:
            progress_cb(10, f"Starting Nuclei scan against {hostname}...")

        # Check nuclei is available
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0 and "nuclei" not in result.stderr.lower():
                raise FileNotFoundError
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("nuclei.not_found", target=hostname)
            return self._unavailable(hostname, "The nuclei binary is not installed.")

        # Update templates silently first
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-silent"],
                capture_output=True, timeout=60,
            )
        except Exception:
            pass

        if progress_cb:
            progress_cb(20, "Running Nuclei templates...")

        try:
            result = subprocess.run(
                [
                    "nuclei",
                    "-u", scan_url,
                    "-tags", self.DEFAULT_TAGS,
                    "-severity", "critical,high,medium,low,info",
                    "-json",
                    "-silent",
                    "-no-color",
                    "-timeout", "10",
                    "-rate-limit", "50",
                    "-bulk-size", "10",
                    "-concurrency", "10",
                    "-max-host-error", "30",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if progress_cb:
                progress_cb(85, "Parsing Nuclei results...")

            findings = _parse_nuclei_jsonl(result.stdout, scan_url)

            if progress_cb:
                progress_cb(100, f"Nuclei complete — {len(findings)} findings")

            logger.info("nuclei.complete", target=hostname, findings=len(findings))
            # No template matches is a real result, not a failure.
            return empty_or_demo(findings, "nuclei",
                                 lambda: self._demo_results(hostname))

        except subprocess.TimeoutExpired:
            logger.warning("nuclei.timeout", target=hostname)
            return self._unavailable(
                hostname, "The nuclei scan exceeded its time limit and was stopped."
            )
        except Exception as e:
            logger.error("nuclei.error", target=hostname, error=str(e))
            return self._unavailable(hostname, f"The nuclei scan failed: {e}.")

    def _unavailable(self, hostname: str, reason: str) -> list[dict]:
        return fallback(
            "Nuclei", "nuclei", reason,
            "Install nuclei in the scanner image to enable template-based CVE "
            "and misconfiguration detection.",
            lambda: self._demo_results(hostname),
        )

    def _demo_results(self, hostname: str) -> list[dict]:
        logger.info("nuclei.using_demo_results", target=hostname)
        return [
            {
                "title": "Nuclei: Apache HTTP Server default page",
                "source": "nuclei", "severity": "LOW",
                "cve_id": None, "cwe_id": "CWE-200",
                "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1595",
                "description": "The Apache HTTP server default page is visible, indicating "
                               "the server may not be properly configured.",
                "evidence": f"Default Apache page detected at https://{hostname}/",
                "remediation": "Replace the default Apache page with your application content. "
                               "Verify web server configuration.",
                "references": [],
            },
            {
                "title": "Nuclei: SSL/TLS certificate expiry check",
                "source": "nuclei", "severity": "INFO",
                "cve_id": None, "cwe_id": "CWE-298",
                "owasp_category": "A02",
                "killchain_phase": "delivery", "mitre_technique_id": "T1040",
                "description": "TLS certificate validity has been checked for the target host.",
                "evidence": f"Certificate inspection on {hostname}:443",
                "remediation": "Ensure certificate is renewed before expiry. "
                               "Consider automated renewal via Let's Encrypt.",
                "references": [],
            },
            {
                "title": "Nuclei: Missing security headers detected",
                "source": "nuclei", "severity": "MEDIUM",
                "cve_id": None, "cwe_id": "CWE-693",
                "owasp_category": "A05",
                "killchain_phase": "delivery", "mitre_technique_id": "T1557",
                "description": "One or more security headers are absent from HTTP responses, "
                               "reducing defence against common web attacks.",
                "evidence": f"Header audit of {hostname} via Nuclei http/misconfiguration templates",
                "remediation": "Add Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security headers.",
                "references": ["https://owasp.org/www-project-secure-headers/"],
            },
        ]
