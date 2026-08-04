import asyncio
import re
import socket
import subprocess
import structlog

from app.services.scanners.availability import empty_or_demo

logger = structlog.get_logger()

RISKY_SUBS = {"admin","dev","staging","test","backup","phpmyadmin","old","sql","db","panel","dashboard","login"}

COMMON_SUBS = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop","vpn",
    "remote","portal","app","beta","old","backup","demo","static","assets","cdn",
    "db","sql","phpmyadmin","panel","dashboard","login","secure","ns1","ns2",
]


_dig_available: bool | None = None


def dig_available() -> bool:
    """Whether the `dig` binary exists, checked once per process.

    This matters for correctness, not just performance: every DNS record check
    here treats an empty result as "record absent". With no dig binary every
    lookup returns empty, and the scanner would confidently report missing
    SPF, DMARC, DNSSEC and CAA records for a domain that has all four.
    """
    global _dig_available
    if _dig_available is None:
        try:
            subprocess.run(["dig", "-v"], capture_output=True, timeout=5)
            _dig_available = True
        except Exception:
            _dig_available = False
            logger.warning("dns.dig_unavailable")
    return _dig_available


def _dig(hostname: str, rtype: str) -> list[str]:
    if not dig_available():
        return []
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=5", rtype, hostname],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _resolve(hostname: str) -> list[str]:
    try:
        return list(set(r[4][0] for r in socket.getaddrinfo(hostname, None, socket.AF_INET)))
    except Exception:
        return []


class DNSScanner:
    """DNS configuration auditor and passive subdomain enumerator."""

    async def scan(self, target: str, progress_cb=None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run, target, progress_cb)

    def _run(self, target: str, progress_cb=None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        findings = []

        if not _resolve(hostname):
            findings.append(self._f(
                "DNS resolution failed", "HIGH",
                f"Could not resolve {hostname}.",
                "Verify DNS configuration and that the domain is active.",
                "CWE-350", "A05", "reconnaissance",
            ))
            return findings

        # Record checks below infer "missing" from an empty dig result, so
        # without the binary they must be suppressed rather than reported.
        # Subdomain enumeration uses the system resolver and still runs.
        dig_ok = dig_available()
        if not dig_ok:
            findings.append(self._f(
                "DNS record audit skipped", "INFO",
                "The 'dig' utility is unavailable in the scanner environment, so "
                "SPF, DMARC, DNSSEC, CAA and zone-transfer checks could not run. "
                "The absence of those findings does not mean the records are "
                "correctly configured.",
                "Install dnsutils/bind-utils in the scanner image to enable the "
                "full DNS audit.",
                "CWE-1059", "A05", "reconnaissance",
            ))

        if progress_cb:
            progress_cb(20, "Checking SPF records...")

        # SPF
        txt = _dig(hostname, "TXT")
        spf = [r for r in txt if "v=spf1" in r.lower()]
        if not spf:
            # Only an *observed* absence is a finding; with no dig binary we
            # simply did not look.
            if dig_ok:
                findings.append(self._f(
                    "SPF record missing", "MEDIUM",
                    "No SPF record found. Domain is vulnerable to email spoofing and phishing.",
                    "Add TXT record: v=spf1 include:_spf.yourmailprovider.com -all",
                    "CWE-350", "A05", "delivery",
                ))
        else:
            spf_val = spf[0]
            if "+all" in spf_val:
                findings.append(self._f(
                    "SPF record uses +all (permissive)", "HIGH",
                    "SPF policy +all permits ANY server to send mail as this domain.",
                    "Replace +all with -all (hardfail) or ~all (softfail).",
                    "CWE-350", "A05", "delivery",
                ))
            elif "~all" in spf_val:
                findings.append(self._f(
                    "SPF record uses ~all (softfail)", "LOW",
                    "SPF softfail allows unauthorised senders but marks them. Consider -all.",
                    "Upgrade SPF from ~all to -all for stricter enforcement.",
                    "CWE-350", "A05", "delivery",
                ))

        if progress_cb:
            progress_cb(40, "Checking DMARC...")

        # DMARC
        dmarc_recs = _dig(f"_dmarc.{hostname}", "TXT")
        dmarc = [r for r in dmarc_recs if "v=dmarc1" in r.lower()]
        if not dmarc:
            if dig_ok:
                findings.append(self._f(
                    "DMARC record missing", "MEDIUM",
                    "No DMARC policy. Attackers can spoof this domain in phishing emails.",
                    "Add: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
                    "CWE-350", "A05", "delivery",
                ))
        elif "p=none" in dmarc[0].lower():
            findings.append(self._f(
                "DMARC policy is p=none (monitor only)", "MEDIUM",
                "DMARC p=none only monitors — spoofed emails are not rejected.",
                "Escalate DMARC from p=none → p=quarantine → p=reject.",
                "CWE-350", "A05", "delivery",
            ))

        if progress_cb:
            progress_cb(55, "Checking DNSSEC and CAA...")

        # DNSSEC
        if dig_ok and not _dig(hostname, "DS") and not _dig(hostname, "DNSKEY"):
            findings.append(self._f(
                "DNSSEC not configured", "LOW",
                "DNS responses cannot be cryptographically verified. Vulnerable to cache poisoning.",
                "Enable DNSSEC through your domain registrar and DNS provider.",
                "CWE-345", "A05", "delivery",
            ))

        # CAA
        if dig_ok and not _dig(hostname, "CAA"):
            findings.append(self._f(
                "CAA record missing", "LOW",
                "No CAA record. Any CA can issue TLS certificates for this domain.",
                "Add CAA record: 0 issue \"letsencrypt.org\"",
                "CWE-295", "A02", "weaponization",
            ))

        if progress_cb:
            progress_cb(70, "Attempting zone transfer...")

        # Zone transfer
        for ns in _dig(hostname, "NS")[:2]:
            ns = ns.rstrip(".")
            try:
                r = subprocess.run(
                    ["dig", f"@{ns}", "AXFR", hostname],
                    capture_output=True, text=True, timeout=10,
                )
                lines = [l for l in r.stdout.splitlines() if l and not l.startswith(";")]
                if len(lines) > 5 and "Transfer failed" not in r.stdout:
                    findings.append(self._f(
                        f"DNS zone transfer allowed from {ns}",
                        "CRITICAL",
                        f"AXFR zone transfer permitted from {ns}. Full DNS zone is exposed including all subdomains.",
                        "Restrict AXFR to authorised secondary nameservers only.",
                        "CWE-200", "A05", "reconnaissance",
                    ))
            except Exception:
                pass

        if progress_cb:
            progress_cb(85, "Enumerating subdomains...")

        # Subdomain enumeration
        for sub in COMMON_SUBS:
            fqdn = f"{sub}.{hostname}"
            ips = _resolve(fqdn)
            if ips and sub in RISKY_SUBS:
                findings.append(self._f(
                    f"Sensitive subdomain exposed: {fqdn}",
                    "MEDIUM",
                    f"{fqdn} resolves to {ips[0]}. May expose dev/admin/staging environments publicly.",
                    f"Ensure {fqdn} is secured and not publicly accessible if unneeded.",
                    "CWE-200", "A05", "reconnaissance",
                ))

        if progress_cb:
            progress_cb(100, "DNS scan complete")

        return empty_or_demo(findings, "dns_scanner",
                             lambda: self._demo_results(hostname))

    def _f(self, title, severity, description, remediation, cwe, owasp, phase):
        return {
            "title": title, "source": "dns_scanner",
            "severity": severity, "cwe_id": cwe,
            "owasp_category": owasp, "killchain_phase": phase,
            "mitre_technique_id": "T1590",
            "description": description, "remediation": remediation,
            "evidence": "DNS query analysis",
            "references": ["https://mxtoolbox.com/", "https://dnschecker.org/"],
        }

    def _demo_results(self, hostname: str) -> list[dict]:
        return [
            self._f("SPF record missing","MEDIUM",
                    "No SPF record. Domain vulnerable to email spoofing.",
                    "Add TXT: v=spf1 include:_spf.google.com -all",
                    "CWE-350","A05","delivery"),
            self._f("DMARC record missing","MEDIUM",
                    "No DMARC policy. Phishing attacks possible.",
                    "Add _dmarc TXT: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
                    "CWE-350","A05","delivery"),
            self._f("DNSSEC not configured","LOW",
                    "DNS cache poisoning is possible without DNSSEC.",
                    "Enable DNSSEC via your domain registrar.",
                    "CWE-345","A05","delivery"),
        ]
