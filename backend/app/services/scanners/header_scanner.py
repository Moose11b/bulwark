import asyncio
import re
import ssl
import structlog
import httpx

from app.services.scanners.availability import fallback, empty_or_demo

logger = structlog.get_logger()

HEADERS_DB = {
    "Content-Security-Policy": {
        "severity": "HIGH", "owasp": "A03", "cwe": "CWE-79",
        "phase": "exploitation", "mitre": "T1059", "weight": 30,
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM", "owasp": "A02", "cwe": "CWE-319",
        "phase": "delivery", "mitre": "T1557", "weight": 25,
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM", "owasp": "A05", "cwe": "CWE-1021",
        "phase": "exploitation", "mitre": "T1185", "weight": 15,
        "remediation": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors 'none'",
    },
    "X-Content-Type-Options": {
        "severity": "LOW", "owasp": "A05", "cwe": "CWE-430",
        "phase": "exploitation", "mitre": "T1059", "weight": 10,
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW", "owasp": "A05", "cwe": "CWE-116",
        "phase": "reconnaissance", "mitre": "T1592", "weight": 10,
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW", "owasp": "A05", "cwe": "CWE-732",
        "phase": "exploitation", "mitre": "T1113", "weight": 10,
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}

DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Runtime",
]

GRADE_MAP = [(90,"A+"),(80,"A"),(70,"B"),(60,"C"),(50,"D"),(0,"F")]


class HeaderScanner:
    """HTTP security response header analyser."""

    async def scan(self, target: str, progress_cb=None, pinned_ip: str | None = None,
                   port: int | None = None, credential=None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        findings = []

        from app.core.pinned_connection import pinned_async_client

        # An explicit port is authoritative. hostname stays bare so the pinned
        # transport still matches on url.host, which excludes the port.
        authority = f"{hostname}:{port}" if port else hostname

        for scheme in ("https", "http"):
            try:
                async with pinned_async_client(
                    hostname, pinned_ip, credential,
                    timeout=15,
                    headers={"User-Agent": "Bulwark-Scanner/2.0"},
                ) as client:
                    resp = await client.get(f"{scheme}://{authority}/")
                    headers = dict(resp.headers)
                break
            except Exception:
                headers = {}

        if not headers:
            # The host never responded over HTTP or HTTPS, so nothing was
            # measured — that is a coverage gap, not a clean header audit.
            return fallback(
                "HTTP header", "header_scanner",
                f"{hostname} did not respond over HTTP or HTTPS.",
                "Confirm the host is reachable and serving traffic on port 80 or 443.",
                self._demo_results,
            )

        score = 100
        for header, meta in HEADERS_DB.items():
            present = any(k.lower() == header.lower() for k in headers)
            if not present:
                score -= meta["weight"]
                findings.append({
                    "title": f"Missing security header: {header}",
                    "source": "header_scanner",
                    "severity": meta["severity"],
                    "cwe_id": meta["cwe"],
                    "owasp_category": meta["owasp"],
                    "killchain_phase": meta["phase"],
                    "mitre_technique_id": meta["mitre"],
                    "description": f"The {header} security header is not set on HTTP responses from {hostname}.",
                    "evidence": f"GET {scheme}://{hostname}/ — no {header} header in response",
                    "remediation": meta["remediation"],
                    "references": ["https://securityheaders.com/", "https://owasp.org/www-project-secure-headers/"],
                })

        # Unsafe CSP directives
        csp = next((v for k, v in headers.items() if k.lower() == "content-security-policy"), "")
        for unsafe in ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]:
            if unsafe in csp:
                findings.append({
                    "title": f"Unsafe CSP directive: {unsafe}",
                    "source": "header_scanner",
                    "severity": "MEDIUM",
                    "cwe_id": "CWE-79",
                    "owasp_category": "A03",
                    "killchain_phase": "exploitation",
                    "mitre_technique_id": "T1059",
                    "description": f"Content-Security-Policy contains '{unsafe}' which weakens XSS protections.",
                    "evidence": f"CSP: {csp[:200]}",
                    "remediation": f"Remove {unsafe} from CSP. Use nonces or hashes for inline scripts.",
                    "references": ["https://content-security-policy.com/"],
                })

        # Server / tech disclosure
        for dh in DISCLOSURE_HEADERS:
            val = next((v for k, v in headers.items() if k.lower() == dh.lower()), "")
            if val:
                findings.append({
                    "title": f"Server information disclosure: {dh}",
                    "source": "header_scanner",
                    "severity": "LOW",
                    "cwe_id": "CWE-200",
                    "owasp_category": "A05",
                    "killchain_phase": "reconnaissance",
                    "mitre_technique_id": "T1592",
                    "description": f"{dh}: {val[:120]} — reveals technology stack to attackers.",
                    "evidence": f"Response header {dh}: {val[:120]}",
                    "remediation": f"Remove or obfuscate the {dh} response header in your web server config.",
                    "references": [],
                })

        # Wildcard CORS
        acao = next((v for k, v in headers.items() if k.lower() == "access-control-allow-origin"), "")
        if acao.strip() == "*":
            findings.append({
                "title": "Wildcard CORS policy",
                "source": "header_scanner",
                "severity": "MEDIUM",
                "cwe_id": "CWE-942",
                "owasp_category": "A05",
                "killchain_phase": "exploitation",
                "mitre_technique_id": "T1059",
                "description": "Access-Control-Allow-Origin: * allows any origin to read cross-origin responses.",
                "evidence": "Access-Control-Allow-Origin: *",
                "remediation": "Restrict CORS to specific trusted origins.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            })

        grade = next(g for threshold, g in GRADE_MAP if max(0, score) >= threshold)
        logger.info("header_scanner.complete", hostname=hostname, score=score, grade=grade, findings=len(findings))

        return empty_or_demo(findings, "header_scanner", self._demo_results)

    def _demo_results(self) -> list[dict]:
        return [
            {
                "title": "Missing security header: Content-Security-Policy",
                "source": "header_scanner", "severity": "HIGH",
                "cwe_id": "CWE-79", "owasp_category": "A03",
                "killchain_phase": "exploitation", "mitre_technique_id": "T1059",
                "description": "No CSP header set. XSS attacks not mitigated by browser.",
                "evidence": "Demo — CSP header absent",
                "remediation": "Add: Content-Security-Policy: default-src 'self'",
                "references": ["https://content-security-policy.com/"],
            },
            {
                "title": "Missing security header: Strict-Transport-Security",
                "source": "header_scanner", "severity": "MEDIUM",
                "cwe_id": "CWE-319", "owasp_category": "A02",
                "killchain_phase": "delivery", "mitre_technique_id": "T1557",
                "description": "HSTS not set. Browsers may allow HTTP downgrade.",
                "evidence": "Demo — HSTS header absent",
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "references": [],
            },
            {
                "title": "Server information disclosure: X-Powered-By",
                "source": "header_scanner", "severity": "LOW",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1592",
                "description": "X-Powered-By: PHP/8.1.2 reveals technology stack.",
                "evidence": "Demo — X-Powered-By: PHP/8.1.2",
                "remediation": "Remove X-Powered-By header in PHP config.",
                "references": [],
            },
        ]
