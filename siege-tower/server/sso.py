"""
Optional OIDC single sign-on for the standalone app.

Authorization-Code flow against any OIDC provider (Keycloak, Authentik, Entra
ID, Okta, Google, …). Disabled unless configured via env:

  SIEGE_OIDC_ISSUER          e.g. https://idp.example.com/realms/main
  SIEGE_OIDC_CLIENT_ID
  SIEGE_OIDC_CLIENT_SECRET
  SIEGE_OIDC_REDIRECT_URI    e.g. https://siege.example.com/api/auth/sso/callback
  SIEGE_OIDC_LABEL           button label (default "Single sign-on")
  SIEGE_OIDC_AUTO_PROVISION  "1" to create a local user on first valid login
  SIEGE_OIDC_DEFAULT_ROLE    role for auto-provisioned users (default operator)

The security-critical step — verifying the ID token (signature, issuer,
audience, expiry, nonce) — is a pure function (`decode_id_token`) so it can be
unit-tested with a known key. Network calls (discovery, token exchange, JWKS)
happen only when SSO is configured and used, and never on import.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from urllib.parse import urlencode


def _env(name: str) -> str | None:
    return os.environ.get(name)


LABEL = _env("SIEGE_OIDC_LABEL") or "Single sign-on"
AUTO_PROVISION = _env("SIEGE_OIDC_AUTO_PROVISION") == "1"
DEFAULT_ROLE = _env("SIEGE_OIDC_DEFAULT_ROLE") or "operator"


def enabled() -> bool:
    return all(_env(k) for k in (
        "SIEGE_OIDC_ISSUER", "SIEGE_OIDC_CLIENT_ID",
        "SIEGE_OIDC_CLIENT_SECRET", "SIEGE_OIDC_REDIRECT_URI"))


_disc_cache: dict | None = None


def discovery() -> dict:
    global _disc_cache
    if _disc_cache is None:
        import urllib.request
        url = _env("SIEGE_OIDC_ISSUER").rstrip("/") + "/.well-known/openid-configuration"
        with urllib.request.urlopen(url, timeout=15) as r:  # noqa: S310
            _disc_cache = json.loads(r.read().decode("utf-8"))
    return _disc_cache


# state -> (nonce, expires_at); short-lived, in-process (single worker).
_states: dict[str, tuple[str, float]] = {}


def new_state() -> tuple[str, str]:
    now = time.time()
    for k, (_n, exp) in list(_states.items()):
        if exp < now:
            _states.pop(k, None)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    _states[state] = (nonce, now + 600)
    return state, nonce


def pop_state(state: str) -> str | None:
    v = _states.pop(state, None)
    if not v or v[1] < time.time():
        return None
    return v[0]


def authorize_url(state: str, nonce: str) -> str:
    d = discovery()
    q = {
        "response_type": "code", "client_id": _env("SIEGE_OIDC_CLIENT_ID"),
        "redirect_uri": _env("SIEGE_OIDC_REDIRECT_URI"),
        "scope": "openid profile email", "state": state, "nonce": nonce,
    }
    return d["authorization_endpoint"] + "?" + urlencode(q)


def exchange_code(code: str) -> dict:
    import urllib.request
    d = discovery()
    data = urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": _env("SIEGE_OIDC_REDIRECT_URI"),
        "client_id": _env("SIEGE_OIDC_CLIENT_ID"),
        "client_secret": _env("SIEGE_OIDC_CLIENT_SECRET"),
    }).encode()
    req = urllib.request.Request(
        d["token_endpoint"], data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
        return json.loads(r.read().decode("utf-8"))


def decode_id_token(id_token: str, key, *, audience: str, issuer: str,
                    nonce: str | None) -> dict:
    """Verify and decode an OIDC ID token. Pure (no network): the caller passes
    the resolved signing key. Raises on any failure (bad signature, wrong
    audience/issuer, expiry, or nonce mismatch)."""
    import jwt
    claims = jwt.decode(
        id_token, key, algorithms=["RS256", "ES256"],
        audience=audience, issuer=issuer,
        options={"require": ["exp", "iat", "aud", "iss"]},
    )
    if nonce is not None and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return claims


def verify_id_token(id_token: str, nonce: str | None) -> dict:
    """Resolve the signing key from the provider's JWKS and verify the token."""
    import jwt
    d = discovery()
    jwks = jwt.PyJWKClient(d["jwks_uri"])
    key = jwks.get_signing_key_from_jwt(id_token).key
    return decode_id_token(
        id_token, key,
        audience=_env("SIEGE_OIDC_CLIENT_ID"),
        issuer=d.get("issuer") or _env("SIEGE_OIDC_ISSUER"),
        nonce=nonce)


def claims_identity(claims: dict) -> dict:
    return {
        "sub": claims.get("sub"),
        "username": (claims.get("preferred_username") or claims.get("email")
                     or claims.get("sub")),
        "email": claims.get("email"),
    }
