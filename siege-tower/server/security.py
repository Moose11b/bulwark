"""
Security primitives for the Siege Tower standalone app.

Everything here is defence for the thin web/server tier — the planning engine
itself stays dependency-free and untouched. This module provides:

  * password hashing (PBKDF2-HMAC-SHA256, constant-time verification),
  * opaque session tokens (random, stored only as a SHA-256 hash),
  * optional application-level encryption of the engagement data blob
    (Fernet, key from SIEGE_ENCRYPTION_KEY), with graceful, *loud* degradation,
  * an in-process rate limiter, and
  * security-headers/CSP and body-size middleware.

None of it touches a target or runs anything — it only protects stored data and
the API surface.

Run ``python -m server.security keygen`` to mint an encryption key.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sys
import time
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger("siege.security")

MIN_PASSWORD_LENGTH = 12


# ── Password hashing ─────────────────────────────────────────────

_PBKDF2_ROUNDS = 600_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Return a self-describing PBKDF2 hash: ``pbkdf2_sha256$rounds$salt$hash``."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify a password against a stored PBKDF2 hash."""
    try:
        algo, rounds_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, rounds)
    return hmac.compare_digest(dk, expected)


# ── Session tokens ───────────────────────────────────────────────

def new_token() -> str:
    """A fresh, unguessable bearer token to hand to a client."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only the hash of a token is ever stored, so a DB leak can't be replayed."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── At-rest encryption of the engagement blob ────────────────────

_ENC_PREFIX = "enc:v1:"


class Encryptor:
    """Encrypts/decrypts the engagement JSON blob with a symmetric key.

    Key comes from ``SIEGE_ENCRYPTION_KEY`` (a urlsafe-base64 32-byte Fernet
    key). If unset, encryption is disabled and a prominent warning is logged;
    data is stored as plaintext JSON so existing installs keep working, but the
    operator is told exactly how to turn protection on. Reads transparently
    handle both encrypted and legacy-plaintext rows.
    """

    def __init__(self) -> None:
        self._fernet = None
        key = os.environ.get("SIEGE_ENCRYPTION_KEY")
        if key:
            try:
                from cryptography.fernet import Fernet
            except ImportError:
                self._warn(
                    "SIEGE_ENCRYPTION_KEY is set but the 'cryptography' package "
                    "is not installed. Install it (pip install 'siege-tower[server]') "
                    "to encrypt engagement data at rest. Storing PLAINTEXT."
                )
            else:
                try:
                    self._fernet = Fernet(key.encode("utf-8"))
                except Exception as exc:  # invalid key material
                    raise RuntimeError(
                        "SIEGE_ENCRYPTION_KEY is invalid. Generate one with "
                        "`python -m server.security keygen`."
                    ) from exc
        else:
            self._warn(
                "No SIEGE_ENCRYPTION_KEY set — engagement data is stored "
                "UNENCRYPTED at rest. Generate a key with "
                "`python -m server.security keygen`, set SIEGE_ENCRYPTION_KEY, "
                "and restart to protect client names, targets, and notes."
            )

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plaintext: str) -> str:
        if not self._fernet:
            return plaintext
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return _ENC_PREFIX + token

    def decrypt(self, value: str) -> str:
        if value.startswith(_ENC_PREFIX):
            if not self._fernet:
                raise RuntimeError(
                    "Found encrypted engagement data but SIEGE_ENCRYPTION_KEY is "
                    "not set (or 'cryptography' is missing). Restore the key used "
                    "to write this database."
                )
            token = value[len(_ENC_PREFIX):].encode("ascii")
            return self._fernet.decrypt(token).decode("utf-8")
        # Legacy plaintext row.
        return value

    @staticmethod
    def _warn(msg: str) -> None:
        banner = "!" * 72
        log.warning("%s", msg)
        print(f"\n{banner}\nSIEGE TOWER SECURITY: {msg}\n{banner}", flush=True)


def generate_key() -> str:
    """Mint a fresh Fernet key (requires 'cryptography')."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("ascii")


# ── Rate limiting (in-process, fixed window) ─────────────────────

class RateLimiter:
    """A simple per-key fixed-window limiter.

    In-process only: correct for a single worker. For multi-worker/hosted
    deployments, front the app with a shared limiter (nginx, a gateway, or a
    Redis-backed limiter). Documented, not silently wrong.
    """

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> bool:
        """Return True if the call is allowed, False if it should be rejected."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits[key]
            keep_from = 0
            for keep_from, t in enumerate(hits):
                if t >= cutoff:
                    break
            else:
                keep_from = len(hits)
            del hits[:keep_from]
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


# ── Security headers + CSP middleware ────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds a strict CSP and the standard hardening headers to every response.

    The CSP allows scripts only from same-origin (the UI ships its JS as an
    external file, so no 'unsafe-inline' for scripts), styles from same-origin
    plus Google Fonts, and fonts from gstatic. `hsts=True` once served over TLS.
    """

    def __init__(self, app, hsts: bool = False) -> None:
        super().__init__(app)
        self._hsts = hsts
        self._csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        )

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", self._csp)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        if self._hsts:
            h.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies before they are parsed or stored."""

    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        {"detail": "Request body too large"}, status_code=413
                    )
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
        return await call_next(request)


def _main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "keygen":
        try:
            print(generate_key())
            return 0
        except ImportError:
            print(
                "The 'cryptography' package is required. Install with "
                "pip install 'siege-tower[server]'.",
                file=sys.stderr,
            )
            return 1
    print("usage: python -m server.security keygen", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
