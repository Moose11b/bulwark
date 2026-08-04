import asyncio
import re
import structlog
import httpx

from app.services.scanners.availability import empty_or_demo

logger = structlog.get_logger()

PATHS = [
    ("/.env",              "CRITICAL", "Environment file exposed. May contain DB passwords and API keys."),
    ("/.env.production",   "CRITICAL", "Production .env file exposed."),
    ("/.env.backup",       "CRITICAL", "Backup .env file exposed."),
    ("/.git/HEAD",         "HIGH",     "Git repository exposed. Source code and history may be downloadable."),
    ("/.git/config",       "HIGH",     "Git config exposed. May reveal repository URLs and credentials."),
    ("/wp-config.php",     "CRITICAL", "WordPress config exposed. Contains DB credentials and auth keys."),
    ("/wp-config.php.bak", "CRITICAL", "WordPress config backup exposed."),
    ("/config.php",        "HIGH",     "PHP config file exposed. May contain DB credentials."),
    ("/settings.py",       "HIGH",     "Django settings exposed. May contain SECRET_KEY and DB credentials."),
    ("/database.yml",      "HIGH",     "Rails database config exposed. May contain DB credentials."),
    ("/web.config",        "HIGH",     "IIS web.config may expose connection strings and secrets."),
    ("/composer.json",     "LOW",      "PHP dependency manifest exposed. Reveals framework versions."),
    ("/package.json",      "LOW",      "Node.js package.json exposed. Reveals tech stack."),
    ("/requirements.txt",  "LOW",      "Python requirements exposed. Reveals library versions."),
    ("/admin",             "MEDIUM",   "Admin panel path accessible. Verify authentication is enforced."),
    ("/wp-admin/",         "MEDIUM",   "WordPress admin panel exposed."),
    ("/phpmyadmin/",       "HIGH",     "phpMyAdmin publicly accessible. Database admin interface exposed."),
    ("/adminer.php",       "HIGH",     "Adminer database tool exposed."),
    ("/backup/",           "HIGH",     "Backup directory accessible. May contain sensitive data."),
    ("/backup.zip",        "CRITICAL", "Site backup archive exposed."),
    ("/db.sql",            "CRITICAL", "SQL database dump exposed. Full database contents at risk."),
    ("/database.sql",      "CRITICAL", "SQL database dump exposed."),
    ("/swagger",           "MEDIUM",   "Swagger UI exposed. Full API documentation accessible."),
    ("/swagger-ui.html",   "MEDIUM",   "Swagger UI exposed."),
    ("/openapi.json",      "MEDIUM",   "OpenAPI spec exposed. Full API surface revealed."),
    ("/graphql",           "INFO",     "GraphQL endpoint accessible. Verify introspection is disabled."),
    ("/actuator",          "HIGH",     "Spring Boot Actuator exposed. Can expose env vars and heap dumps."),
    ("/actuator/env",      "CRITICAL", "Spring Actuator /env exposed. All environment variables accessible."),
    ("/actuator/heapdump", "CRITICAL", "Heap dump endpoint exposed. Memory contents downloadable."),
    ("/server-status",     "HIGH",     "Apache server-status exposed. Reveals current requests and server info."),
    ("/.htaccess",         "MEDIUM",   ".htaccess accessible. May reveal security config and URL rules."),
    ("/.DS_Store",         "LOW",      ".DS_Store exposed. Reveals directory structure (macOS artifact)."),
    ("/robots.txt",        "INFO",     "robots.txt accessible. Review for disallowed paths revealing structure."),
    ("/error.log",         "HIGH",     "Error log exposed. May contain stack traces with credentials."),
    ("/debug.log",         "HIGH",     "Debug log exposed. May contain sensitive application data."),
]

API_KEY_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)(aws[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI API Key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'&]{8,})', "Password"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'(?i)(secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret key"),
]


class ExposureScanner:
    """Sensitive file and secret exposure checker."""

    async def scan(self, target: str, progress_cb=None, pinned_ip: str | None = None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        base_url = f"https://{hostname}"
        findings = []

        from app.core.pinned_connection import pinned_async_client

        async with pinned_async_client(
            hostname, pinned_ip,
            follow_redirects=False,
            timeout=8,
            headers={"User-Agent": "Bulwark-Scanner/2.0"},
        ) as client:
            tasks = [self._check(client, base_url, path, severity, desc)
                     for path, severity, desc in PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        # Check index page for API key leaks
        try:
            async with pinned_async_client(hostname, pinned_ip, timeout=10) as client:
                index_body = await self._read_capped(client, f"{base_url}/")
                for pattern, key_type in API_KEY_PATTERNS:
                    if index_body and re.search(pattern, index_body):
                        findings.append({
                            "title": f"{key_type} leaked in page source",
                            "source": "exposure_scanner",
                            "severity": "CRITICAL",
                            "cwe_id": "CWE-312",
                            "owasp_category": "A02",
                            "killchain_phase": "reconnaissance",
                            "mitre_technique_id": "T1552",
                            "description": f"A {key_type} pattern was detected in the main page HTML/JavaScript.",
                            "evidence": f"Pattern match in GET {base_url}/",
                            "remediation": "Move secrets server-side. Never embed credentials in client-side code.",
                            "references": ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
                        })
                        break
        except Exception:
            pass

        if progress_cb:
            progress_cb(100, f"Exposure scan complete — {len(findings)} findings")

        return empty_or_demo(findings, "exposure_scanner", self._demo_results)

    # Cap on how much of a response body we will pull into memory. The scan
    # target is untrusted and 35 of these run concurrently, so a hostile or
    # merely large /backup.zip must not be buffered in full.
    MAX_BODY_BYTES = 512_000

    async def _read_capped(self, client, url: str) -> str:
        """Stream a response body, abandoning it once it exceeds the cap.

        Returns "" if the body is oversized or unreadable, so callers simply
        skip content inspection rather than buffering a hostile payload.
        """
        try:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return ""
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > self.MAX_BODY_BYTES:
                        return ""
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return ""

    async def _check(self, client, base_url, path, severity, description) -> list[dict]:
        findings = []
        try:
            body = ""
            async with client.stream("GET", f"{base_url}{path}") as resp:
                if resp.status_code not in (200, 403):
                    return []
                if resp.status_code == 200:
                    chunks, size = [], 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > self.MAX_BODY_BYTES:
                            chunks = []          # oversized: skip secret scan
                            break
                        chunks.append(chunk)
                    if chunks:
                        body = b"".join(chunks).decode("utf-8", errors="replace")

            if resp.status_code == 403:
                # Path exists but forbidden — downgrade to LOW
                severity = "LOW"
                description = f"Path {path} exists (403 Forbidden). Presence confirmed."

            if resp.status_code == 200:
                findings.append({
                    "title": f"Sensitive path accessible: {path}",
                    "source": "exposure_scanner",
                    "severity": severity,
                    "cwe_id": "CWE-200",
                    "owasp_category": "A05",
                    "killchain_phase": "reconnaissance",
                    "mitre_technique_id": "T1083",
                    "description": description,
                    "evidence": f"HTTP GET {base_url}{path} returned {resp.status_code}",
                    "remediation": f"Restrict access to {path} via web server config or move outside web root.",
                    "references": [],
                })

                # Check content for secrets (empty when over the size cap)
                if body:
                    for pattern, key_type in API_KEY_PATTERNS:
                        if re.search(pattern, body):
                            findings.append({
                                "title": f"{key_type} exposed in {path}",
                                "source": "exposure_scanner",
                                "severity": "CRITICAL",
                                "cwe_id": "CWE-312",
                                "owasp_category": "A02",
                                "killchain_phase": "reconnaissance",
                                "mitre_technique_id": "T1552",
                                "description": f"A {key_type} credential pattern was detected in the contents of {path}.",
                                "evidence": f"Regex match in response body of {path}",
                                "remediation": f"Immediately revoke the exposed {key_type}. Remove secrets from web-accessible files.",
                                "references": [],
                            })
                            break

                if "Index of" in body or "directory listing" in body.lower():
                    findings.append({
                        "title": f"Directory listing enabled: {path}",
                        "source": "exposure_scanner",
                        "severity": "MEDIUM",
                        "cwe_id": "CWE-548",
                        "owasp_category": "A05",
                        "killchain_phase": "reconnaissance",
                        "mitre_technique_id": "T1083",
                        "description": f"Directory listing is active at {path}. File tree is browsable.",
                        "evidence": f"'Index of' detected in response body",
                        "remediation": "Disable directory listing: Options -Indexes (Apache) or autoindex off (Nginx).",
                        "references": [],
                    })
        except Exception:
            pass
        return findings

    def _demo_results(self) -> list[dict]:
        return [
            {
                "title": "Sensitive path accessible: /.git/HEAD",
                "source": "exposure_scanner", "severity": "HIGH",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1083",
                "description": "Git repository exposed. Source code and history may be downloadable.",
                "evidence": "Demo — HTTP 200 at /.git/HEAD",
                "remediation": "Block access to .git directory in web server config.",
                "references": [],
            },
            {
                "title": "Sensitive path accessible: /swagger-ui.html",
                "source": "exposure_scanner", "severity": "MEDIUM",
                "cwe_id": "CWE-200", "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1083",
                "description": "Swagger UI exposed. Full API documentation and endpoint list accessible.",
                "evidence": "Demo — HTTP 200 at /swagger-ui.html",
                "remediation": "Restrict Swagger UI to internal networks or authenticated users only.",
                "references": [],
            },
        ]
