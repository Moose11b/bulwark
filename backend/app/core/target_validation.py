"""
Target validation — SSRF protection.

Bulwark makes outbound requests (HTTP, DNS, Shodan, Nmap) against whatever
target string a user submits. Without validation, a user could point the
scanner at internal infrastructure, cloud metadata endpoints, or loopback
services and turn Bulwark into an SSRF / internal-recon weapon.

This module resolves a target and rejects anything that points at:
  - loopback (127.0.0.0/8, ::1)
  - private RFC1918 ranges (10/8, 172.16/12, 192.168/16)
  - link-local (169.254/16) — includes cloud metadata 169.254.169.254
  - CGNAT (100.64/10)
  - unique-local / link-local IPv6 (fc00::/7, fe80::/10)
  - reserved / multicast / unspecified
  - known cloud metadata hostnames

It also enforces a hostname/format allowlist so a target can't smuggle in
schemes, credentials, ports to internal services, or DNS-rebind tricks.
"""
import ipaddress
import re
import socket
import structlog
from typing import NamedTuple

logger = structlog.get_logger()


class TargetValidationError(ValueError):
    """Raised when a scan target fails security validation."""
    pass


class ValidatedTarget(NamedTuple):
    """A target that passed SSRF validation.

    port is None when the target named no port, letting each scanner apply its
    own protocol default. Carrying it explicitly matters: normalisation used to
    discard the port entirely, so `http://app:8080` was scanned as
    `http://app:80` — the wrong service, reported as if it were the right one.
    """
    host: str
    port: int | None
    pinned_ip: str | None


def format_target(host: str, port: int | None) -> str:
    """Render host/port back into a single storable target string."""
    return f"{host}:{port}" if port else host


# Cloud metadata + internal service hostnames that must never be scanned
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}

# Internal TLDs that should never resolve externally
BLOCKED_TLDS = {".internal", ".local", ".localhost", ".cluster.local", ".svc"}

# Docker-internal service names from our own compose stack
BLOCKED_SERVICE_NAMES = {
    "postgres", "redis", "backend", "worker", "beat", "flower", "frontend",
    "db", "database", "cache", "broker",
}

# Hostname must look like a real domain or a bare IP
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _strip_target(raw: str) -> tuple[str, int | None]:
    """Remove scheme, credentials, and path — return (host, port).

    The port is returned rather than discarded so scanners connect to the
    service the user actually named.
    """
    t = raw.strip()
    # Reject embedded credentials (user:pass@host) outright
    if "@" in t.split("/")[0].replace("https://", "").replace("http://", ""):
        raise TargetValidationError("Targets must not contain credentials (user@host).")
    # Strip scheme
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", t)
    # Strip path / query / fragment
    t = t.split("/")[0].split("?")[0].split("#")[0]

    port: int | None = None
    # Exactly one colon is host:port. More than one means an IPv6 literal,
    # which is left intact so the explicit IPv6 rejection below can see it.
    if t.count(":") == 1:
        host_part, _, port_part = t.partition(":")
        if port_part.isdigit():
            parsed = int(port_part)
            if not 1 <= parsed <= 65535:
                raise TargetValidationError(
                    f"Port {parsed} is out of range (1-65535)."
                )
            t, port = host_part, parsed
        else:
            # Colons are not valid in hostnames, so a single colon followed by
            # a non-numeric value is a malformed port. Reject it explicitly —
            # it would otherwise fall through to the IPv6 check and produce a
            # confusing "IPv6 literal not supported" message.
            raise TargetValidationError(
                f"'{port_part}' is not a valid port number."
            )

    return t.strip().lower().rstrip("."), port


def _ip_is_blocked(ip_str: str) -> tuple[bool, str]:
    """Return (blocked, reason) for an IP address string."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"'{ip_str}' is not a valid IP address"

    if ip.is_loopback:
        return True, "loopback addresses are not scannable"
    if ip.is_private:
        return True, "private/internal addresses are not scannable"
    if ip.is_link_local:
        return True, "link-local addresses (incl. cloud metadata) are not scannable"
    if ip.is_multicast:
        return True, "multicast addresses are not scannable"
    if ip.is_reserved:
        return True, "reserved addresses are not scannable"
    if ip.is_unspecified:
        return True, "unspecified addresses are not scannable"
    # CGNAT 100.64.0.0/10
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True, "carrier-grade NAT addresses are not scannable"
    # Explicit metadata IP
    if ip_str == "169.254.169.254":
        return True, "cloud metadata endpoint is blocked"

    return False, ""


def validate_target(raw: str, *, resolve: bool = True, allow_private: bool = False) -> str:
    """
    Validate and normalise a scan target.

    Returns the cleaned hostname/IP if safe.
    Raises TargetValidationError if the target is unsafe or malformed.

    Set resolve=False to skip DNS resolution (e.g. in unit tests).
    Set allow_private=True ONLY for trusted local/CI scans where the operator
    explicitly authorises scanning internal/loopback addresses. This is OFF
    by default; real user-facing paths must never enable it.

    NOTE: This returns host[:port] with no pinned IP. There is a theoretical
    TOCTOU window — a hostname validated here could be re-resolved to a
    different (internal) IP when a scanner later connects (DNS rebinding).
    For paths that act on the target, prefer validate_target_pinned(), which
    returns the exact validated IP so the caller can pin the connection.
    """
    result = _validate(raw, resolve=resolve, allow_private=allow_private)
    # Keep the port in the normalised string so callers that persist this
    # value (assets, scans) can round-trip it back through validation.
    return format_target(result.host, result.port)


def validate_target_pinned(raw: str, *, resolve: bool = True,
                           allow_private: bool = False) -> ValidatedTarget:
    """
    Validate a target and return ValidatedTarget(host, port, pinned_ip).

    pinned_ip is the single IP address that passed validation. Callers
    should connect to THIS IP (sending the hostname as a Host header / SNI)
    rather than re-resolving the hostname, which closes the DNS-rebinding
    TOCTOU gap: even if the attacker's DNS flips to an internal address
    after validation, the scanner only ever touches the IP we already
    confirmed is public.

    For a bare-IP target, pinned_ip == hostname. If resolve=False,
    pinned_ip is None (test mode).

    Set allow_private=True ONLY for trusted local/CI scans (see
    validate_target). OFF by default.
    """
    return _validate(raw, resolve=resolve, allow_private=allow_private)


def _validate(raw: str, *, resolve: bool = True,
              allow_private: bool = False) -> ValidatedTarget:
    if not raw or not raw.strip():
        raise TargetValidationError("Target is required.")

    host, port = _strip_target(raw)

    if not host:
        raise TargetValidationError("Could not parse a hostname from the target.")

    if len(host) > 253:
        raise TargetValidationError("Target hostname is too long.")

    # When explicitly authorised (local/CI), skip the internal-address
    # blocks but still parse/normalise the target.
    if allow_private:
        if _IPV4_RE.match(host):
            return ValidatedTarget(host, port, host)
        if resolve:
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_INET)
                ips = {info[4][0] for info in infos}
                return ValidatedTarget(host, port, sorted(ips)[0] if ips else None)
            except socket.gaierror:
                return ValidatedTarget(host, port, None)
        return ValidatedTarget(host, port, None)

    # Block obvious internal names
    if host in BLOCKED_HOSTNAMES:
        raise TargetValidationError(f"'{host}' is an internal host and cannot be scanned.")
    if host in BLOCKED_SERVICE_NAMES:
        raise TargetValidationError(f"'{host}' is an internal service name and cannot be scanned.")
    for tld in BLOCKED_TLDS:
        if host.endswith(tld):
            raise TargetValidationError(f"Internal TLD '{tld}' cannot be scanned.")

    # Block IPv6 literals (bracketed form). Check the raw only for brackets;
    # the stripped host should never contain a colon (port already removed).
    if "[" in raw or "]" in raw or ":" in host:
        raise TargetValidationError("IPv6 literal targets are not supported.")

    # Case 1: target is a bare IPv4 literal — pinned IP is itself
    if _IPV4_RE.match(host):
        blocked, reason = _ip_is_blocked(host)
        if blocked:
            raise TargetValidationError(f"Target rejected: {reason}.")
        return ValidatedTarget(host, port, host)

    # Case 2: target must be a valid public hostname
    if not _HOSTNAME_RE.match(host):
        raise TargetValidationError(
            f"'{host}' is not a valid public domain or IPv4 address."
        )

    # Resolve and check every A record — defeats DNS rebinding to internal IPs
    if resolve:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
        except socket.gaierror:
            raise TargetValidationError(f"'{host}' could not be resolved via DNS.")

        resolved_ips = {info[4][0] for info in infos}
        if not resolved_ips:
            raise TargetValidationError(f"'{host}' did not resolve to any address.")

        for ip_str in resolved_ips:
            blocked, reason = _ip_is_blocked(ip_str)
            if blocked:
                logger.warning(
                    "target.ssrf_blocked", host=host, resolved_ip=ip_str, reason=reason
                )
                raise TargetValidationError(
                    f"Target '{host}' resolves to a blocked address ({reason})."
                )

        # Pin the first validated IP. Every resolved IP passed the check,
        # so any is safe; the caller connects to this exact address rather
        # than re-resolving, closing the rebind window.
        pinned_ip = sorted(resolved_ips)[0]
        return ValidatedTarget(host, port, pinned_ip)

    return ValidatedTarget(host, port, None)
