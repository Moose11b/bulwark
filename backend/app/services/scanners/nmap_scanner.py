import asyncio
import structlog
import nmap

from app.services.scanners.availability import fallback, empty_or_demo

logger = structlog.get_logger()

RISKY_PORTS = {
    21:    ("FTP",          "HIGH",     "FTP transmits credentials in plaintext. Use SFTP instead.", "CWE-319"),
    22:    ("SSH",          "INFO",     "SSH open. Ensure key-based auth and fail2ban are configured.", None),
    23:    ("Telnet",       "CRITICAL", "Telnet transmits all data in plaintext. Disable immediately.", "CWE-319"),
    25:    ("SMTP",         "MEDIUM",   "SMTP open. Ensure relay is restricted to prevent abuse.", "CWE-200"),
    53:    ("DNS",          "INFO",     "DNS port open. Ensure recursion is disabled for public resolvers.", None),
    80:    ("HTTP",         "INFO",     "HTTP open. Ensure all traffic redirects to HTTPS.", "CWE-319"),
    110:   ("POP3",         "MEDIUM",   "POP3 may transmit credentials in plaintext. Use POP3S (995).", "CWE-319"),
    135:   ("MSRPC",        "HIGH",     "Windows RPC exposed. Common lateral movement surface.", "CWE-200"),
    139:   ("NetBIOS",      "HIGH",     "NetBIOS session service exposed. Firewall this port.", "CWE-200"),
    161:   ("SNMP",         "HIGH",     "SNMP exposed. Can leak full network topology. Use SNMPv3.", "CWE-200"),
    389:   ("LDAP",         "HIGH",     "LDAP exposed. May allow unauthenticated enumeration.", "CWE-200"),
    443:   ("HTTPS",        "INFO",     "HTTPS open. Standard and expected.", None),
    445:   ("SMB",          "CRITICAL", "SMB exposed. High risk: EternalBlue, ransomware pivot.", "CWE-732"),
    1433:  ("MSSQL",        "CRITICAL", "SQL Server publicly exposed. Critical data risk.", "CWE-732"),
    1521:  ("Oracle",       "CRITICAL", "Oracle DB exposed. Should never be internet-facing.", "CWE-732"),
    2375:  ("Docker",       "CRITICAL", "Docker daemon exposed without TLS. Full host compromise.", "CWE-732"),
    3306:  ("MySQL",        "CRITICAL", "MySQL publicly exposed. Restrict to localhost or VPN.", "CWE-732"),
    3389:  ("RDP",          "CRITICAL", "RDP exposed. Top target for brute force and ransomware.", "CWE-732"),
    5432:  ("PostgreSQL",   "CRITICAL", "PostgreSQL publicly exposed. Restrict to localhost or VPN.", "CWE-732"),
    5900:  ("VNC",          "HIGH",     "VNC exposed. Ensure strong password and VPN-only access.", "CWE-732"),
    6379:  ("Redis",        "CRITICAL", "Redis exposed. Often unauthenticated. Critical data risk.", "CWE-732"),
    8080:  ("HTTP-Alt",     "MEDIUM",   "Alternate HTTP port open. May expose dev/admin services.", "CWE-200"),
    8443:  ("HTTPS-Alt",    "LOW",      "Alternate HTTPS port open.", None),
    8888:  ("Jupyter",      "HIGH",     "Jupyter Notebook may be exposed. Full server compromise risk.", "CWE-732"),
    9200:  ("Elasticsearch","CRITICAL", "Elasticsearch exposed. Typically unauthenticated.", "CWE-732"),
    27017: ("MongoDB",      "CRITICAL", "MongoDB exposed. Historically exploited with no auth.", "CWE-732"),
}

OWASP_MAP = {
    "CRITICAL": "A05", "HIGH": "A05", "MEDIUM": "A05",
    "LOW": "A05", "INFO": "A05",
}

KILLCHAIN_MAP = {
    "CRITICAL": "exploitation", "HIGH": "reconnaissance",
    "MEDIUM": "reconnaissance", "LOW": "reconnaissance", "INFO": "reconnaissance",
}


class NmapScanner:
    """Async wrapper around python-nmap for port scanning."""

    async def scan(self, target: str, progress_cb=None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_nmap, target, progress_cb)

    def _unavailable(self, target: str, reason: str) -> list[dict]:
        return fallback(
            "Port scan", "nmap", reason,
            "Install nmap in the scanner image (apt-get install nmap) to enable "
            "port and service discovery.",
            lambda: self._demo_results(target),
        )

    def _run_nmap(self, target: str, progress_cb=None) -> list[dict]:
        findings = []

        # PortScanner() raises when the nmap binary is not on PATH. Keep it
        # inside the guard: an uncaught error here propagates all the way to
        # the orchestrator and discards every other scanner's results.
        try:
            nm = nmap.PortScanner()
        except Exception as e:
            logger.warning("nmap.binary_unavailable", target=target, error=str(e))
            return self._unavailable(target, "The nmap binary is not installed.")

        if progress_cb:
            progress_cb(10, "Running Nmap port scan...")

        try:
            nm.scan(
                hosts=target,
                arguments="-sV -sC --open -T4 --top-ports 1000 --script=banner",
                timeout=300,
            )
        except Exception as e:
            logger.error("nmap.scan_error", target=target, error=str(e))
            return self._unavailable(target, f"The nmap scan failed: {e}.")

        try:
            findings.extend(self._parse_hosts(nm, target))
        except Exception as e:
            logger.error("nmap.parse_error", target=target, error=str(e))
            return self._unavailable(target, f"Nmap output could not be parsed: {e}.")

        if progress_cb:
            progress_cb(100, f"Port scan complete — {len(findings)} findings")

        # No open risky ports is a real, reportable result — not a gap.
        return empty_or_demo(findings, "nmap", lambda: self._demo_results(target))

    def _parse_hosts(self, nm, target: str) -> list[dict]:
        findings = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = nm[host][proto][port]
                    if port_data["state"] != "open":
                        continue

                    service = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    banner  = port_data.get("script", {}).get("banner", "")

                    if int(port) in RISKY_PORTS:
                        svc_name, severity, remediation, cwe = RISKY_PORTS[int(port)]
                        if severity == "INFO":
                            continue
                        findings.append({
                            "title": f"Open port {port}: {svc_name}",
                            "source": "nmap",
                            "severity": severity,
                            "cwe_id": cwe,
                            "owasp_category": OWASP_MAP.get(severity, "A05"),
                            "killchain_phase": KILLCHAIN_MAP.get(severity, "reconnaissance"),
                            "mitre_technique_id": "T1595",
                            "description": (
                                f"Port {port}/{proto} ({svc_name}) is open and reachable. "
                                f"{f'Service: {product} {version}. ' if product else ''}"
                                f"{f'Banner: {banner[:200]}' if banner else ''}"
                            ),
                            "evidence": f"nmap -sV scan confirmed port {port}/{proto} open on {host}",
                            "remediation": remediation,
                            "references": [
                                f"https://www.shodan.io/search?query=port%3A{port}",
                            ],
                        })
                    elif product or version:
                        # Unknown port but with a detected service — log as info
                        findings.append({
                            "title": f"Open port {port}: {service}",
                            "source": "nmap",
                            "severity": "INFO",
                            "cwe_id": "CWE-200",
                            "owasp_category": "A05",
                            "killchain_phase": "reconnaissance",
                            "mitre_technique_id": "T1595",
                            "description": (
                                f"Port {port}/{proto} open. "
                                f"Service: {service} {product} {version}."
                            ),
                            "evidence": f"nmap detected open port {port}/{proto} on {host}",
                            "remediation": "Verify this port should be publicly accessible. Close if not needed.",
                            "references": [],
                        })

        return findings

    def _demo_results(self, target: str) -> list[dict]:
        logger.info("nmap.using_demo_results", target=target)
        return [
            {
                "title": "Open port 22: SSH",
                "source": "nmap", "severity": "INFO",
                "cwe_id": None, "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1595",
                "description": "SSH port 22 open. Ensure key-based auth only.",
                "evidence": "Demo result", "remediation": "Disable password auth. Use SSH keys.",
                "references": [],
            },
            {
                "title": "Open port 443: HTTPS",
                "source": "nmap", "severity": "INFO",
                "cwe_id": None, "owasp_category": "A05",
                "killchain_phase": "reconnaissance", "mitre_technique_id": "T1595",
                "description": "HTTPS port 443 open. Standard and expected.",
                "evidence": "Demo result", "remediation": "N/A",
                "references": [],
            },
            {
                "title": "Open port 3306: MySQL",
                "source": "nmap", "severity": "CRITICAL",
                "cwe_id": "CWE-732", "owasp_category": "A05",
                "killchain_phase": "exploitation", "mitre_technique_id": "T1190",
                "description": "MySQL port 3306 publicly exposed. Critical data exfiltration risk.",
                "evidence": "Demo result",
                "remediation": "Restrict MySQL to localhost or internal VPN only. Never expose port 3306 publicly.",
                "references": ["https://nvd.nist.gov/vuln/search/results?query=mysql+exposed"],
            },
        ]
