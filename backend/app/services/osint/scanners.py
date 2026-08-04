"""
Passive OSINT services. All read-only — no interaction with target.
"""
import asyncio
import re
import httpx
import structlog
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


# ── crt.sh — certificate transparency ────────────────────────────

class CRTScanner:
    async def scan(self, target: str) -> dict:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        domain = ".".join(hostname.split(".")[-2:])
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"},
                )
                certs = resp.json()

            subdomains = set()
            issuers = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for n in name.splitlines():
                    n = n.strip().lstrip("*.")
                    if domain in n:
                        subdomains.add(n)
                issuer = cert.get("issuer_name", "")
                if issuer:
                    issuers.add(issuer.split("CN=")[-1].split(",")[0])

            return {
                "domain": domain,
                "subdomain_count": len(subdomains),
                "subdomains": sorted(subdomains)[:100],
                "issuers": list(issuers)[:10],
                "cert_count": len(certs),
            }
        except Exception as e:
            logger.debug("crt.error", domain=domain, error=str(e))
            return {"domain": domain, "subdomains": [], "error": str(e)}


# ── WHOIS / ASN ──────────────────────────────────────────────────

class WhoisScanner:
    async def scan(self, target: str) -> dict:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        domain = ".".join(hostname.split(".")[-2:])
        result = {}

        try:
            # ipwhois / RDAP for domain
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(f"https://rdap.org/domain/{domain}")
                data = resp.json()
                result["registrar"] = next(
                    (e.get("fn") for e in data.get("entities", [])
                     if "registrar" in (e.get("roles") or [])), None
                )
                events = {e["eventAction"]: e["eventDate"]
                          for e in data.get("events", [])}
                result["registered"] = events.get("registration")
                result["expires"]    = events.get("expiration")
                result["updated"]    = events.get("last changed")
                result["status"]     = data.get("status", [])
        except Exception:
            pass

        try:
            # IP geolocation via ip-api.com
            import socket
            ip = socket.gethostbyname(hostname)
            result["ip"] = ip
            async with httpx.AsyncClient(timeout=10) as client:
                geo = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as")
                geo_data = geo.json()
                result["country"]  = geo_data.get("country")
                result["isp"]      = geo_data.get("isp")
                result["org"]      = geo_data.get("org")
                result["asn"]      = geo_data.get("as")
        except Exception:
            pass

        return result


# ── HaveIBeenPwned ────────────────────────────────────────────────

class HIBPScanner:
    async def scan(self, target: str) -> dict:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        domain = ".".join(hostname.split(".")[-2:])

        if not settings.hibp_api_key:
            return {"domain": domain, "breaches": [], "note": "HIBP API key not configured"}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                    headers={
                        "hibp-api-key": settings.hibp_api_key,
                        "User-Agent": "Bulwark-Scanner/2.0",
                    },
                )
                if resp.status_code == 404:
                    return {"domain": domain, "breaches": [], "breach_count": 0}
                if resp.status_code == 401:
                    return {"domain": domain, "breaches": [], "note": "Invalid HIBP API key"}

                data = resp.json()
                breaches = []
                for breach_name, emails in data.items():
                    breaches.append({
                        "name": breach_name,
                        "email_count": len(emails),
                    })

                return {
                    "domain": domain,
                    "breach_count": len(breaches),
                    "breaches": breaches,
                    "total_emails_exposed": sum(b["email_count"] for b in breaches),
                }
        except Exception as e:
            logger.debug("hibp.error", domain=domain, error=str(e))
            return {"domain": domain, "breaches": [], "error": str(e)}


# ── VirusTotal ────────────────────────────────────────────────────

class VirusTotalScanner:
    async def scan(self, target: str) -> dict:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]

        if not settings.virustotal_api_key:
            return {"hostname": hostname, "note": "VirusTotal API key not configured"}

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{hostname}",
                    headers={"x-apikey": settings.virustotal_api_key},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "hostname": hostname,
                        "malicious":  stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless":   stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": data.get("reputation", 0),
                        "categories": data.get("categories", {}),
                    }
                return {"hostname": hostname, "note": f"VT returned {resp.status_code}"}
        except Exception as e:
            return {"hostname": hostname, "error": str(e)}


# ── Wayback Machine ───────────────────────────────────────────────

class WaybackScanner:
    async def scan(self, target: str) -> dict:
        hostname = re.sub(r'^https?://', '', target).split('/')[0]
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"{hostname}/*",
                        "output": "json",
                        "fl": "original,timestamp,statuscode",
                        "limit": 200,
                        "collapse": "urlkey",
                        "filter": "statuscode:200",
                    },
                )
                rows = resp.json()

            if not rows or len(rows) < 2:
                return {"hostname": hostname, "snapshots": []}

            snapshots = []
            interesting = [".env", ".git", "admin", "backup", "config", "api", "swagger", ".sql", "phpmyadmin"]
            flagged = []

            for row in rows[1:]:
                url, ts, status = row[0], row[1], row[2]
                year = ts[:4] if ts else "?"
                snapshots.append({"url": url, "year": year, "status": status})
                if any(p in url.lower() for p in interesting):
                    flagged.append(url)

            return {
                "hostname": hostname,
                "total_snapshots": len(snapshots),
                "oldest_year": min((s["year"] for s in snapshots), default="?"),
                "flagged_paths": flagged[:20],
                "snapshot_sample": snapshots[:20],
            }
        except Exception as e:
            return {"hostname": hostname, "error": str(e)}
