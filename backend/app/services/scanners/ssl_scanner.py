import asyncio
import ssl
import socket
import datetime
import re
import structlog

from app.services.scanners.availability import empty_or_demo

logger = structlog.get_logger()


class SSLScanner:
    """SSL/TLS certificate and protocol analyser."""

    async def scan(self, target: str, progress_cb=None, pinned_ip: str | None = None,
                   port: int | None = None, credential=None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._run, target, progress_cb, pinned_ip, port, credential
        )

    def _run(self, target: str, progress_cb=None, pinned_ip: str | None = None,
             port: int | None = None, credential=None) -> list[dict]:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        # TLS lives on 443 unless the target named another port.
        tls_port = port or 443
        findings = []

        # Connect to the pinned (validated) IP if provided, but keep SNI +
        # cert checks bound to the hostname. This closes the DNS-rebind gap:
        # we never re-resolve the hostname at connect time.
        from app.core.pinned_connection import revalidate_ip
        connect_host = pinned_ip if (pinned_ip and revalidate_ip(pinned_ip)) else hostname

        if progress_cb:
            progress_cb(10, "Connecting to SSL/TLS endpoint...")

        # ── Raw connection (no cert verification) ────────────────
        try:
            raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            raw_ctx.check_hostname = False
            raw_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((connect_host, tls_port), timeout=10) as sock:
                with raw_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else ""
                    cipher_bits = cipher_info[2] if cipher_info else 128

            # Protocol version
            deprecated = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            if protocol in deprecated:
                findings.append(self._f(
                    f"Deprecated TLS version in use: {protocol}",
                    "HIGH",
                    f"Server negotiated {protocol} which is cryptographically weak.",
                    "Disable TLS 1.0 and 1.1. Configure server to accept only TLS 1.2 and TLS 1.3.",
                    "CWE-326", "A02", "delivery", "T1040",
                ))

            # Weak ciphers
            weak = ["RC4", "DES", "EXPORT", "NULL", "anon", "MD5"]
            for w in weak:
                if w in cipher_name:
                    findings.append(self._f(
                        f"Weak cipher suite: {cipher_name}",
                        "CRITICAL",
                        f"Server is using cipher {cipher_name} which contains the insecure component {w}.",
                        "Disable RC4, DES, EXPORT, and NULL cipher suites immediately.",
                        "CWE-327", "A02", "exploitation", "T1040",
                    ))
                    break

            if cipher_bits and cipher_bits < 128:
                findings.append(self._f(
                    f"Insufficient cipher key length: {cipher_bits}-bit",
                    "HIGH",
                    f"Cipher {cipher_name} uses only {cipher_bits}-bit keys, below the 128-bit minimum.",
                    "Use AES-256-GCM or CHACHA20-POLY1305 cipher suites.",
                    "CWE-326", "A02", "delivery", "T1040",
                ))

        except (ConnectionRefusedError, socket.timeout, OSError):
            findings.append(self._f(
                f"HTTPS not available on port {tls_port}",
                "HIGH",
                f"Port {tls_port} is not open or HTTPS is not configured.",
                "Enable HTTPS and obtain a valid TLS certificate.",
                "CWE-319", "A02", "delivery", "T1557",
            ))
            return findings
        except Exception as e:
            logger.debug("ssl.raw_error", error=str(e))

        if progress_cb:
            progress_cb(50, "Checking certificate validity...")

        # ── Validated connection ──────────────────────────────────
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((connect_host, tls_port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.datetime.utcnow()).days
                    exp_str = exp.strftime("%Y-%m-%d")

                    if days < 0:
                        findings.append(self._f(
                            f"SSL certificate expired {abs(days)} days ago",
                            "CRITICAL",
                            f"Certificate expired on {exp_str}. All browsers will show a security error.",
                            "Renew the SSL certificate immediately.",
                            "CWE-298", "A02", "exploitation", "T1557",
                        ))
                    elif days < 14:
                        findings.append(self._f(
                            f"SSL certificate expiring in {days} days",
                            "HIGH",
                            f"Certificate expires on {exp_str}. Imminent outage risk.",
                            "Renew the SSL certificate before expiry.",
                            "CWE-298", "A02", "reconnaissance", "T1590",
                        ))
                    elif days < 30:
                        findings.append(self._f(
                            f"SSL certificate expiring in {days} days",
                            "MEDIUM",
                            f"Certificate expires on {exp_str}.",
                            "Schedule certificate renewal.",
                            "CWE-298", "A02", "reconnaissance", "T1590",
                        ))

        except ssl.SSLCertVerificationError as e:
            findings.append(self._f(
                "SSL certificate verification failed",
                "HIGH",
                str(e),
                "Obtain a valid certificate from a trusted CA.",
                "CWE-295", "A02", "exploitation", "T1557",
            ))
        except Exception:
            pass

        if progress_cb:
            progress_cb(80, "Checking HSTS...")

        # ── HSTS check ────────────────────────────────────────────
        try:
            import asyncio as _asyncio
            from app.core.pinned_connection import pinned_async_client

            async def _fetch_hsts():
                async with pinned_async_client(
                    hostname, pinned_ip, credential,
                    timeout=10,
                    headers={"User-Agent": "Bulwark-Scanner/2.0"},
                ) as client:
                    authority = f"{hostname}:{tls_port}" if tls_port != 443 else hostname
                    r = await client.get(f"https://{authority}/")
                    return r.headers.get("Strict-Transport-Security", "")

            # _run executes in a thread executor, so there is no loop here and
            # one must be created. It has to be closed too — the previous code
            # leaked a selector fd and its sockets on every SSL scan, which a
            # long-lived Celery worker eventually pays for with EMFILE.
            _loop = _asyncio.new_event_loop()
            try:
                hsts = _loop.run_until_complete(_fetch_hsts())
            finally:
                try:
                    _loop.run_until_complete(_loop.shutdown_asyncgens())
                finally:
                    _loop.close()

            if not hsts:
                findings.append(self._f(
                    "HSTS header missing",
                    "MEDIUM",
                    "Strict-Transport-Security header is not set. Browsers may allow HTTP downgrade attacks.",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "CWE-319", "A05", "delivery", "T1557",
                ))
            elif "preload" not in hsts:
                findings.append(self._f(
                    "HSTS not submitted for preloading",
                    "LOW",
                    "HSTS header present but preload directive missing.",
                    "Add 'preload' to HSTS header and submit domain to hstspreload.org.",
                    "CWE-319", "A05", "delivery", "T1557",
                ))
        except Exception:
            pass

        if progress_cb:
            progress_cb(100, "SSL scan complete")

        return empty_or_demo(findings, "ssl_scanner",
                             lambda: self._demo_results(hostname))

    def _f(self, title, severity, description, remediation, cwe, owasp, phase, mitre):
        return {
            "title": title, "source": "ssl_scanner",
            "severity": severity, "cwe_id": cwe,
            "owasp_category": owasp, "killchain_phase": phase,
            "mitre_technique_id": mitre,
            "description": description, "remediation": remediation,
            "evidence": "SSL/TLS handshake analysis",
            "references": ["https://testssl.sh/", "https://www.ssllabs.com/ssltest/"],
        }

    def _demo_results(self, hostname: str) -> list[dict]:
        return [
            self._f(
                "HSTS header missing", "MEDIUM",
                "Strict-Transport-Security not set. HTTP downgrade possible.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "CWE-319", "A05", "delivery", "T1557",
            ),
            self._f(
                "HSTS not submitted for preloading", "LOW",
                "HSTS present but 'preload' directive missing.",
                "Add preload to HSTS and submit to hstspreload.org.",
                "CWE-319", "A05", "delivery", "T1557",
            ),
        ]
