"""
Issuer trust and OIDC verification.

The single most important property here: a token is only ever trusted if it
comes from an issuer the operator configured. Everything verifies against real
RS256 signatures — no mocking of the crypto — with only the JWKS/discovery
network fetch stubbed.
"""
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.utils import long_to_base64

from app.config import get_settings
from app.core import auth as auth_mod
from app.core import oidc as oidc_mod

CLERK_ISSUER = "https://loved-jaguar-55.clerk.accounts.dev"
OIDC_ISSUER = "https://id.example.com/realms/main"


def _keypair(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
        "n": long_to_base64(nums.n).decode(),
        "e": long_to_base64(nums.e).decode(),
    }
    return pem, jwk


def _token(private_pem, kid, *, iss, sub, aud=None, extra=None):
    claims = {"iss": iss, "sub": sub, "iat": int(time.time()), "exp": int(time.time()) + 300}
    if aud:
        claims["aud"] = aud
    if extra:
        claims.update(extra)
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture(autouse=True)
def _clear_caches():
    auth_mod._jwks_cache.clear()
    oidc_mod._jwks_cache.clear()
    oidc_mod._discovery_cache.clear()
    yield


# ── The bypass, closed ───────────────────────────────────────────

async def test_token_from_untrusted_issuer_is_rejected(monkeypatch):
    """The core fix: an attacker's own issuer must not be trusted.

    Forge a validly-signed token whose iss points at an attacker domain, with
    a victim's subject. The old code fetched the attacker's JWKS and accepted
    it; the allowlist must now reject it before any fetch.
    """
    monkeypatch.setattr(get_settings(), "clerk_publishable_key",
                        "pk_test_bG92ZWQtamFndWFyLTU1LmNsZXJrLmFjY291bnRzLmRldiQ",
                        raising=False)
    monkeypatch.setattr(get_settings(), "clerk_issuer", "", raising=False)

    attacker_pem, attacker_jwk = _keypair("attacker-1")
    forged = _token(attacker_pem, "attacker-1",
                    iss="https://attacker.example.com", sub="user_VICTIM")

    fetched = []

    async def _should_not_fetch(issuer):
        fetched.append(issuer)
        return {"keys": [attacker_jwk]}

    monkeypatch.setattr(auth_mod, "_get_jwks", _should_not_fetch)

    with pytest.raises(Exception) as exc:
        await auth_mod._verify_clerk_token(forged)
    assert exc.value.status_code == 401
    assert "not trusted" in exc.value.detail.lower()
    assert fetched == [], "JWKS was fetched from an untrusted (attacker) issuer"


async def test_valid_clerk_token_from_the_trusted_issuer_is_accepted(monkeypatch):
    monkeypatch.setattr(get_settings(), "clerk_publishable_key",
                        "pk_test_bG92ZWQtamFndWFyLTU1LmNsZXJrLmFjY291bnRzLmRldiQ",
                        raising=False)
    monkeypatch.setattr(get_settings(), "clerk_issuer", "", raising=False)

    pem, jwk = _keypair("clerk-1")
    token = _token(pem, "clerk-1", iss=CLERK_ISSUER, sub="user_REAL")

    async def _jwks(issuer):
        assert issuer == CLERK_ISSUER
        return {"keys": [jwk]}

    monkeypatch.setattr(auth_mod, "_get_jwks", _jwks)

    claims = await auth_mod._verify_clerk_token(token)
    assert claims["sub"] == "user_REAL"


async def test_clerk_token_signed_by_the_wrong_key_is_rejected(monkeypatch):
    """Right issuer, wrong signer — the JWKS won't contain the key."""
    monkeypatch.setattr(get_settings(), "clerk_publishable_key",
                        "pk_test_bG92ZWQtamFndWFyLTU1LmNsZXJrLmFjY291bnRzLmRldiQ",
                        raising=False)
    monkeypatch.setattr(get_settings(), "clerk_issuer", "", raising=False)

    wrong_pem, _ = _keypair("attacker-2")
    _, real_jwk = _keypair("clerk-real")
    token = _token(wrong_pem, "clerk-real", iss=CLERK_ISSUER, sub="user_X")

    async def _jwks(issuer):
        return {"keys": [real_jwk]}  # different key than signed the token

    monkeypatch.setattr(auth_mod, "_get_jwks", _jwks)

    with pytest.raises(Exception) as exc:
        await auth_mod._verify_clerk_token(token)
    assert exc.value.status_code == 401


# ── OIDC verification ────────────────────────────────────────────

async def test_oidc_token_verifies_against_configured_issuer(monkeypatch):
    pem, jwk = _keypair("oidc-1")
    token = _token(pem, "oidc-1", iss=OIDC_ISSUER, sub="alice", aud="bulwark",
                   extra={"email": "alice@example.com"})

    async def _jwks(issuer, *, force=False):
        assert issuer == OIDC_ISSUER
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc_mod, "_jwks", _jwks)

    claims = await oidc_mod.verify_oidc_token(token, issuer=OIDC_ISSUER, audience="bulwark")
    assert claims["sub"] == "alice"
    assert claims["email"] == "alice@example.com"


async def test_oidc_wrong_audience_is_rejected(monkeypatch):
    pem, jwk = _keypair("oidc-2")
    token = _token(pem, "oidc-2", iss=OIDC_ISSUER, sub="bob", aud="some-other-client")

    async def _jwks(issuer, *, force=False):
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc_mod, "_jwks", _jwks)

    from jose import JWTError
    with pytest.raises(JWTError):
        await oidc_mod.verify_oidc_token(token, issuer=OIDC_ISSUER, audience="bulwark")


async def test_oidc_expired_token_is_rejected(monkeypatch):
    pem, jwk = _keypair("oidc-3")
    claims = {"iss": OIDC_ISSUER, "sub": "carol",
              "iat": int(time.time()) - 600, "exp": int(time.time()) - 300}
    token = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "oidc-3"})

    async def _jwks(issuer, *, force=False):
        return {"keys": [jwk]}

    monkeypatch.setattr(oidc_mod, "_jwks", _jwks)

    from jose import JWTError
    with pytest.raises(JWTError):
        await oidc_mod.verify_oidc_token(token, issuer=OIDC_ISSUER, audience=None)


# ── Issuer derivation ────────────────────────────────────────────

def test_clerk_issuer_derived_from_publishable_key(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "clerk_issuer", "", raising=False)
    monkeypatch.setattr(s, "clerk_publishable_key",
                        "pk_test_bG92ZWQtamFndWFyLTU1LmNsZXJrLmFjY291bnRzLmRldiQ",
                        raising=False)
    assert s.clerk_issuer_url == CLERK_ISSUER


def test_explicit_clerk_issuer_overrides_derivation(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "clerk_issuer", "https://custom.clerk.example/", raising=False)
    assert s.clerk_issuer_url == "https://custom.clerk.example"


def test_no_clerk_config_means_no_trusted_issuer(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "clerk_issuer", "", raising=False)
    monkeypatch.setattr(s, "clerk_publishable_key", "", raising=False)
    assert s.clerk_issuer_url is None
