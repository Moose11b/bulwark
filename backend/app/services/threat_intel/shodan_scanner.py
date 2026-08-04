"""
Shodan integration — pulls host exposure data for scan targets.
Surfaces open ports, banners, known vulns, and tags from Shodan's
internet-wide scan data without us actively touching the target.
"""
import asyncio
import re
import socket
import httpx
import structlog
from app.config import get_settings
from app.services.scanners.availability import fallback

logger = structlog.get_logger()
settings = get_settings()

SHODAN_BASE = "https://api.shodan.io"


class ShodanScanner:
    """Passive host intelligence via the Shodan API."""

    def _unavailable(self, target: str, reason: str) -> list[dict]:
        return fallback(
            "Shodan", "shodan", reason,
            "Set SHODAN_API_KEY in your environment to enable passive exposure "
            "intelligence.",
            lambda: self._demo_results(target),
        )

    async def scan(self, target: str, progress_cb=None) -> list[dict]:
        if not settings.shodan_api_key:
            logger.info("shodan.no_api_key")
            return self._unavailable(target, "No Shodan API key is configured.")

        hostname = re.sub(r"^https?://", "", target).split("/")[0]

        # Resolve to IP — Shodan host API takes IPs.
        # socket.gethostbyname is blocking and cannot be given a timeout, so
        # calling it directly stalls the whole event loop — including the
        # Redis progress stream — for as long as the resolver takes. Push it
        # to a thread and bound it.
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=socket.AF_INET),
                timeout=10,
            )
            ip = infos[0][4][0]
        except Exception:
            logger.warning("shodan.resolve_failed", target=hostname)
            return []

        if progress_cb:
            progress_cb(20, f"Querying Shodan for {ip}...")

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{SHODAN_BASE}/shodan/host/{ip}",
                    params={"key": settings.shodan_api_key},
                )
                if resp.status_code == 404:
                    # No info in Shodan for this host — not an error
                    return []
                if resp.status_code != 200:
                    logger.warning("shodan.bad_response", status=resp.status_code)
                    return self._unavailable(
                        target,
                        f"The Shodan API returned HTTP {resp.status_code}.",
                    )
                data = resp.json()

            findings = self._parse_host_data(data, ip, hostname)

            if progress_cb:
                progress_cb(100, f"Shodan complete — {len(findings)} findings")

            return findings

        except Exception as e:
            logger.error("shodan.error", target=hostname, error=str(e))
            return self._unavailable(target, f"The Shodan lookup failed: {e}.")

    def _parse_host_data(self, data: dict, ip: str, hostname: str) -> list[dict]:
        findings = []

        # Known vulnerabilities flagged by Shodan
        vulns = data.get("vulns", [])
        for cve in vulns:
            findings.append({
                "title": f"Shodan: {cve} exposed on {ip}",
                "source": "shodan",
                "severity": "HIGH",
                "cve_id": cve if cve.startswith("CVE-") else None,
                "cwe_id": None,
                "owasp_category": "A06",
                "killchain_phase": "reconnaissance",
                "mitre_technique_id": "T1595",
                "description": (
                    f"Shodan reports host {ip} ({hostname}) is affected by {cve}. "
                    f"This vulnerability is publicly visible in Shodan's scan data, "
                    f"meaning attackers can find it through passive reconnaissance."
                ),
                "evidence": f"Shodan host record for {ip} lists vulnerability {cve}",
                "remediation": (
                    f"Patch {cve} immediately. The exposure is indexed by Shodan and "
                    f"discoverable by anyone."
                ),
                "references": [f"https://www.shodan.io/host/{ip}"],
            })

        # Open ports / services
        for service in data.get("data", []):
            port = service.get("port")
            transport = service.get("transport", "tcp")
            product = service.get("product", "")
            version = service.get("version", "")
            module = service.get("_shodan", {}).get("module", "")

            if product or version:
                findings.append({
                    "title": f"Shodan: {product or module} on port {port}",
                    "source": "shodan",
                    "severity": "INFO",
                    "cve_id": None,
                    "cwe_id": "CWE-200",
                    "owasp_category": "A05",
                    "killchain_phase": "reconnaissance",
                    "mitre_technique_id": "T1592",
                    "description": (
                        f"Shodan has indexed port {port}/{transport} on {ip} running "
                        f"{product} {version}. This service is publicly visible in Shodan."
                    ),
                    "evidence": f"Shodan: port {port}/{transport}, product {product} {version}",
                    "remediation": (
                        "Confirm this service should be internet-facing. If not, firewall it. "
                        "Shodan indexing means it's discoverable without active scanning."
                    ),
                    "references": [f"https://www.shodan.io/host/{ip}"],
                })

        # Exposure tags (e.g. 'self-signed', 'compromised', 'honeypot')
        risky_tags = {"compromised", "malware", "self-signed", "vpn", "database", "ics"}
        for tag in data.get("tags", []):
            if tag.lower() in risky_tags:
                findings.append({
                    "title": f"Shodan tag: {tag}",
                    "source": "shodan",
                    "severity": "MEDIUM",
                    "cve_id": None,
                    "cwe_id": None,
                    "owasp_category": "A05",
                    "killchain_phase": "reconnaissance",
                    "mitre_technique_id": "T1592",
                    "description": f"Shodan has tagged host {ip} with '{tag}'.",
                    "evidence": f"Shodan tag: {tag}",
                    "remediation": f"Investigate why this host is tagged '{tag}' in Shodan.",
                    "references": [f"https://www.shodan.io/host/{ip}"],
                })

        return findings

    def _demo_results(self, target: str) -> list[dict]:
        return [
            {
                "title": "Shodan: nginx 1.18.0 on port 443",
                "source": "shodan", "severity": "INFO",
                "cve_id": None, "cwe_id": "CWE-200",
                "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1592",
                "description": "Shodan has indexed this host's web server. (Demo data — add SHODAN_API_KEY for live results.)",
                "evidence": "Demo Shodan record",
                "remediation": "Confirm internet-facing services are intentional.",
                "references": [],
            },
        ]
