"""Run the Siege Tower app: `python -m server` (or `siege-tower-server`).

Environment:
  SIEGE_HOST            bind address (default 127.0.0.1)
  SIEGE_PORT            bind port (default 8000)
  SIEGE_RELOAD          set to enable autoreload (dev only)
  SIEGE_TLS_CERT/KEY    paths to a cert/key to serve HTTPS
  SIEGE_ALLOW_INSECURE  set to 1 to permit a non-loopback bind without TLS
  SIEGE_ADMIN_USERNAME/PASSWORD, SIEGE_ENCRYPTION_KEY, SIEGE_SESSION_TTL_HOURS
"""
import ipaddress
import os
import sys


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    import uvicorn

    host = os.environ.get("SIEGE_HOST", "127.0.0.1")
    port = int(os.environ.get("SIEGE_PORT", "8000"))
    cert = os.environ.get("SIEGE_TLS_CERT")
    key = os.environ.get("SIEGE_TLS_KEY")
    tls = bool(cert and key)

    # Refuse to expose the app on a non-loopback interface without TLS, unless
    # the operator explicitly opts in. Auth is always on, but plaintext HTTP on
    # a network still leaks tokens and engagement data.
    if not _is_loopback(host) and not tls and os.environ.get("SIEGE_ALLOW_INSECURE") != "1":
        sys.stderr.write(
            f"\nRefusing to bind {host} over plaintext HTTP.\n"
            "Serve TLS by setting SIEGE_TLS_CERT and SIEGE_TLS_KEY, put the app "
            "behind an HTTPS reverse proxy (and set SIEGE_BEHIND_TLS=1), or — for "
            "a trusted private network only — set SIEGE_ALLOW_INSECURE=1.\n\n"
        )
        raise SystemExit(2)

    ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key} if tls else {}
    uvicorn.run(
        "server.app:app",
        host=host,
        port=port,
        reload=bool(os.environ.get("SIEGE_RELOAD")),
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
