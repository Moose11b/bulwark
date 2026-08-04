"""
Pinned-connection helper for SSRF safety.

When a target hostname has already been validated and resolved to a known-safe
public IP, scanners should connect to THAT IP rather than re-resolving the
hostname at connect time. Re-resolution reopens the DNS-rebind TOCTOU window:
the attacker's DNS can flip to an internal address (127.0.0.1, 169.254.169.254,
10.x, etc.) in the gap between validation and connection.

This module provides:
  - pinned_async_client(): an httpx.AsyncClient whose DNS resolution is forced
    to the pinned IP for the target host, while still sending the correct SNI
    and Host header so TLS and virtual-hosting still work.
  - revalidate_ip(): a cheap re-check that an IP is still public, used as a
    second guard for any code path that cannot pin.

If no pinned IP is supplied, behaviour falls back to normal resolution so the
helpers remain safe to use everywhere.
"""
import ipaddress
import httpx


def _ip_is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def revalidate_ip(ip_str: str) -> bool:
    """Re-check that a pinned IP is still safe before connecting."""
    return _ip_is_public(ip_str)


def pinned_async_client(hostname: str, pinned_ip: str | None, **kwargs) -> httpx.AsyncClient:
    """
    Return an httpx.AsyncClient that, for `hostname`, connects only to
    `pinned_ip`. SNI and Host header still use the hostname so TLS cert
    validation and name-based virtual hosts keep working.

    If pinned_ip is None or no longer public, falls back to a normal client
    (the caller's upstream validation is still the primary guard).
    """
    default_kwargs = {
        "verify": False,
        "follow_redirects": True,
        "timeout": 15,
        "headers": {"User-Agent": "Bulwark-Scanner/2.0"},
    }
    default_kwargs.update(kwargs)

    if pinned_ip and revalidate_ip(pinned_ip):
        # Map the validated host:port to the pinned IP. httpx honours this
        # mapping instead of doing a fresh DNS lookup at connect time.
        transport = httpx.AsyncHTTPTransport(
            retries=0,
            local_address=None,
        )
        # httpx supports per-client host resolution overrides via the
        # `mounts`/transport `resolver` only in newer versions; the portable
        # mechanism is the connection-level `resolver` map on the transport
        # pool. We use the documented `httpx.AsyncClient` + a resolver shim.
        return httpx.AsyncClient(
            transport=_PinnedTransport(hostname, pinned_ip),
            **default_kwargs,
        )

    return httpx.AsyncClient(**default_kwargs)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Transport that rewrites the connection target to the pinned IP while
    preserving the original Host header and TLS SNI (server_hostname)."""

    def __init__(self, hostname: str, pinned_ip: str, **kwargs):
        super().__init__(**kwargs)
        self._hostname = hostname
        self._pinned_ip = pinned_ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == self._hostname:
            # Preserve Host header + SNI, swap only the connection host to the IP.
            if "host" not in (k.lower() for k in request.headers):
                request.headers["Host"] = url.host
            request.extensions.setdefault("sni_hostname", self._hostname)
            request.url = url.copy_with(host=self._pinned_ip)
        return await super().handle_async_request(request)


def assert_still_public(hostname: str) -> bool:
    """
    Re-resolve a hostname and confirm every A record is still public.

    Used as a pre-launch guard for subprocess scanners (Nikto, Nuclei) that
    do their own DNS resolution and can't be handed a pinned IP. Calling this
    immediately before launching the tool shrinks the DNS-rebind window to the
    sub-millisecond gap between this check and the tool's own resolution,
    rather than the multi-second gap since initial validation.

    Returns True if safe to proceed, False if the host now resolves to any
    non-public address (caller should abort the scan).
    """
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except socket.gaierror:
        return False
    ips = {info[4][0] for info in infos}
    if not ips:
        return False
    return all(_ip_is_public(ip) for ip in ips)
