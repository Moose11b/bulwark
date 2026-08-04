"""
Standalone scan engine.

Runs Bulwark's scanners with NO database, Redis, or Celery dependency.
This is the path used by the CLI / CI pipeline tool — it returns plain
finding dicts that can be rendered to stdout, JSON, or SARIF.

The full hosted platform uses scan_orchestrator.py (which persists to
Postgres and streams progress via Redis). This module shares the same
scanner modules and the same classification/enrichment logic, so findings
are identical — only the I/O and storage differ.
"""
import asyncio
from datetime import datetime, timezone

# Scanner profiles → which scanners run
PROFILES = {
    "headers": ["header_scanner"],
    "web":     ["header_scanner", "ssl_scanner", "nikto", "nuclei"],
    "network": ["nmap", "ssl_scanner"],
    "full":    ["nmap", "header_scanner", "ssl_scanner", "dns_scanner",
                "nikto", "nuclei", "exposure_scanner"],
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


class StandaloneScanEngine:
    """Run scanners and classify findings without any external services."""

    def __init__(self, *, enrich: bool = True, on_progress=None, allow_private: bool = False):
        self.enrich = enrich
        self._on_progress = on_progress
        self.allow_private = allow_private

    def _progress(self, pct: int, msg: str):
        if self._on_progress:
            self._on_progress(pct, msg)

    async def scan(self, target: str, profile: str = "web") -> dict:
        """
        Run the requested profile against target.
        Returns a result dict: {target, profile, started_at, completed_at,
        duration_seconds, findings: [...], summary: {...}}.
        """
        # Validate target for SSRF safety even in standalone mode.
        # Pin the validated IP to close the DNS-rebind TOCTOU window.
        from app.core.target_validation import (
            validate_target_pinned, format_target, TargetValidationError,
        )
        try:
            validated = validate_target_pinned(
                target, allow_private=self.allow_private
            )
        except TargetValidationError as e:
            raise ValueError(f"Target validation failed: {e}")

        clean_target = validated.host
        port = validated.port
        pinned_ip = validated.pinned_ip

        scanners = PROFILES.get(profile, PROFILES["web"])
        started = datetime.now(timezone.utc)
        all_findings: list[dict] = []

        step = 0
        total = len(scanners)
        for name in scanners:
            step += 1
            base_pct = int((step - 1) / total * 80)
            self._progress(base_pct, f"Running {name}...")
            try:
                findings = await self._run_scanner(name, clean_target, pinned_ip, port)
                all_findings.extend(findings)
            except Exception as e:
                # A single scanner failing shouldn't abort the whole run
                self._progress(base_pct, f"{name} error: {e}")

        # Classify + enrich
        self._progress(85, "Classifying findings...")
        enriched = await self._classify(all_findings)

        if self.enrich:
            self._progress(92, "Enriching with CVE intelligence...")
            enriched = await self._enrich_cves(enriched)

        completed = datetime.now(timezone.utc)
        self._progress(100, "Scan complete")

        return {
            # Report the target as actually scanned, port included.
            "target": format_target(clean_target, port),
            "pinned_ip": pinned_ip,
            "profile": profile,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "duration_seconds": round((completed - started).total_seconds(), 1),
            "findings": enriched,
            "summary": self._summarise(enriched),
            "tool": "bulwark",
        }

    async def _run_scanner(self, name: str, target: str, pinned_ip: str | None = None,
                           port: int | None = None) -> list[dict]:
        """Dynamically import and run a single scanner module."""
        if name == "nmap":
            # nmap discovers ports itself, so an explicit port is not applied.
            from app.services.scanners.nmap_scanner import NmapScanner
            return await NmapScanner().scan(target)
        if name == "header_scanner":
            from app.services.scanners.header_scanner import HeaderScanner
            return await HeaderScanner().scan(target, pinned_ip=pinned_ip, port=port)
        if name == "ssl_scanner":
            from app.services.scanners.ssl_scanner import SSLScanner
            return await SSLScanner().scan(target, pinned_ip=pinned_ip, port=port)
        if name == "dns_scanner":
            # DNS records are per-name, not per-port.
            from app.services.scanners.dns_scanner import DNSScanner
            return await DNSScanner().scan(target)
        if name == "nikto":
            from app.services.scanners.nikto_scanner import NiktoScanner
            return await NiktoScanner().scan(target, pinned_ip=pinned_ip, port=port,
                                             allow_private=self.allow_private)
        if name == "nuclei":
            from app.services.scanners.nuclei_scanner import NucleiScanner
            return await NucleiScanner().scan(target, pinned_ip=pinned_ip, port=port,
                                              allow_private=self.allow_private)
        if name == "exposure_scanner":
            from app.services.scanners.exposure_scanner import ExposureScanner
            return await ExposureScanner().scan(target, pinned_ip=pinned_ip, port=port)
        return []

    async def _classify(self, findings: list[dict]) -> list[dict]:
        """Run OWASP / kill chain / compliance classification (pure, no DB)."""
        from app.services.analysis import (
            classify_vulnerability, classify_to_phase, map_compliance,
        )
        from app.core.audit import sanitize_finding

        out = []
        for f in findings:
            f = sanitize_finding(dict(f))
            owasp, _ = classify_vulnerability(f)
            phase, _ = classify_to_phase(f)
            compliance = map_compliance(f)
            f.update({
                "owasp_category": f.get("owasp_category") or owasp,
                "killchain_phase": f.get("killchain_phase") or phase,
                "pci_dss": compliance.get("pci_dss", []),
                "iso_27001": compliance.get("iso_27001", []),
                "nist_csf": compliance.get("nist_csf", []),
                "cis_v8": compliance.get("cis_v8", []),
            })
            out.append(f)
        return out

    async def _enrich_cves(self, findings: list[dict]) -> list[dict]:
        """Best-effort NVD/EPSS/KEV enrichment. Network failures are non-fatal."""
        try:
            from app.services.enrichment import enrich_findings_list
            return await enrich_findings_list(findings)
        except Exception:
            return findings

    def _summarise(self, findings: list[dict]) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        highest = "INFO"
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(highest, 0):
                highest = sev
        return {
            "total": len(findings),
            "by_severity": counts,
            "highest_severity": highest,
        }


def meets_threshold(summary: dict, fail_on: str) -> bool:
    """Return True if findings meet/exceed the fail-on threshold."""
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK.get(fail_on.upper())
    if threshold is None:
        return False
    counts = summary.get("by_severity", {})
    for sev, rank in SEVERITY_RANK.items():
        if rank >= threshold and counts.get(sev, 0) > 0:
            return True
    return False
