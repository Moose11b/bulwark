"""
Local (built-in) authentication.

The default auth mode for a self-hosted Bulwark: an email/password login that
needs no external identity provider, so `docker compose up` ends at a working
sign-in rather than a wall. OIDC (SSO) and Clerk remain available for teams and
hosted deployments; see config.auth_mode.

Two primitives live here, both standard:

  * Password hashing with bcrypt (used directly rather than through passlib,
    whose 1.7.4 release misdetects bcrypt 5.x and can silently break — not a
    risk worth taking in an auth path).
  * A signed session token: a short-lived HS256 JWT keyed on SECRET_KEY, with a
    fixed `iss` of "bulwark-local" so the auth dependency can route it to this
    verifier and never confuse it with a Clerk/OIDC token.

Nothing here talks to the database; callers own user lookup and persistence.
"""
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import jwt

from app.config import get_settings

settings = get_settings()

# Fixed issuer so get_current_user can route a local token to local
# verification. It is never derived from the token itself.
LOCAL_ISSUER = "bulwark-local"
_ALGORITHM = "HS256"

# bcrypt hashes at most 72 bytes of input; longer passwords are truncated by
# the algorithm anyway, so we truncate explicitly to avoid a ValueError on
# some bcrypt builds and to make the behaviour obvious.
_BCRYPT_MAX = 72


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:_BCRYPT_MAX]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(
            password.encode("utf-8")[:_BCRYPT_MAX],
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        # Malformed stored hash — treat as a failed login, never an error.
        return False


def create_local_token(user_id: str, role: str, email: str,
                       ttl_hours: int | None = None) -> str:
    """Issue a signed session token for a local user."""
    now = datetime.now(timezone.utc)
    ttl = ttl_hours if ttl_hours is not None else settings.local_session_ttl_hours
    claims = {
        "iss": LOCAL_ISSUER,
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ttl)).timestamp()),
    }
    return jwt.encode(claims, settings.secret_key, algorithm=_ALGORITHM)


def verify_local_token(token: str) -> dict:
    """Verify a local session token. Raises jose.JWTError on any problem."""
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[_ALGORITHM],
        issuer=LOCAL_ISSUER,
        options={"verify_aud": False},
    )


# Basic password policy. Deliberately modest — the point is to stop "admin"
# and "password", not to frustrate a self-hoster. Tune via config later if
# there's demand.
MIN_PASSWORD_LENGTH = 10


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in {"password", "changeme", "admin", "bulwark"}:
        problems.append("is too common")
    return problems
