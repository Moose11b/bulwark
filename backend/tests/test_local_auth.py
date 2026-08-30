"""
Local authentication primitives.

Pure and network/DB-free: password hashing, the signed session token, the
password policy, and auth-mode resolution. This is security-critical code, so
the round-trips and the negative cases are pinned down explicitly.
"""
import pytest

from app.core import local_auth
from app.core.local_auth import (
    LOCAL_ISSUER,
    create_local_token,
    hash_password,
    password_problems,
    verify_local_token,
    verify_password,
)


def test_password_hash_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"      # actually hashed
    assert h.startswith("$2")                        # bcrypt
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong", h) is False


def test_verify_password_handles_bad_input():
    assert verify_password("anything", "") is False
    assert verify_password("anything", "not-a-hash") is False


def test_long_password_does_not_raise():
    # bcrypt caps at 72 bytes; we truncate rather than error.
    h = hash_password("A" * 200)
    assert verify_password("A" * 200, h) is True


def test_token_roundtrip_and_claims():
    tok = create_local_token("user-123", "admin", "a@b.com")
    claims = verify_local_token(tok)
    assert claims["sub"] == "user-123"
    assert claims["role"] == "admin"
    assert claims["email"] == "a@b.com"
    assert claims["iss"] == LOCAL_ISSUER


def test_expired_token_rejected():
    from jose import JWTError
    tok = create_local_token("u", "analyst", "a@b.com", ttl_hours=-1)
    with pytest.raises(JWTError):
        verify_local_token(tok)


def test_tampered_token_rejected():
    from jose import JWTError
    tok = create_local_token("u", "analyst", "a@b.com")
    with pytest.raises(JWTError):
        verify_local_token(tok + "x")


def test_token_signed_with_other_secret_rejected(monkeypatch):
    from jose import jwt, JWTError
    forged = jwt.encode(
        {"iss": LOCAL_ISSUER, "sub": "attacker", "role": "admin"},
        "a-different-secret", algorithm="HS256",
    )
    with pytest.raises(JWTError):
        verify_local_token(forged)


def test_password_policy():
    assert password_problems("short") == ["must be at least 10 characters"]
    assert "is too common" in password_problems("password")
    assert password_problems("a-decent-passphrase") == []


# ── auth-mode resolution ─────────────────────────────────────────

def _settings(**over):
    from app.config import Settings
    return Settings(**over)


def test_effective_auth_mode_defaults_to_local():
    assert _settings().effective_auth_mode == "local"


def test_effective_auth_mode_infers_oidc_then_clerk():
    assert _settings(oidc_issuer="https://id.example.com").effective_auth_mode == "oidc"
    assert _settings(clerk_secret_key="sk_test_x").effective_auth_mode == "clerk"


def test_effective_auth_mode_explicit_wins():
    # Explicit local overrides even when Clerk keys are present.
    s = _settings(auth_mode="local", clerk_secret_key="sk_test_x")
    assert s.effective_auth_mode == "local"
