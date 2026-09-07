"""
Authentication & authorization dependencies for the Siege Tower app.

Bearer-token auth: the client sends ``Authorization: Bearer <token>``; the token
is looked up (by hash) in the sessions table, which yields the user and their
org. Because auth rides on a header (not a cookie), the API has no CSRF surface.

Authorization is role-based (admin / operator / viewer) and, above all,
tenant-scoped: `current_org` is derived from the authenticated user, never from
client input, so a caller can only act within its own org.
"""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request

from . import db


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Trusts X-Forwarded-For only when explicitly told
    to (behind a known proxy), to avoid spoofing the rate-limit / audit key."""
    import os
    if os.environ.get("SIEGE_TRUST_PROXY") == "1":
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def current_user(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    user = db.resolve_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session",
                            headers={"WWW-Authenticate": "Bearer"})
    request.state.user = user
    request.state.client_ip = _client_ip(request)
    return user


async def current_org_id(user: dict = Depends(current_user)) -> str:
    return user["org_id"]


def require_role(*roles: str):
    """Dependency factory: require the user to hold one of ``roles``.

    Roles are ordered admin > operator > viewer; a higher role satisfies a lower
    requirement.
    """
    order = {"viewer": 0, "operator": 1, "admin": 2}
    needed = min(order[r] for r in roles)

    async def _dep(user: dict = Depends(current_user)) -> dict:
        if order.get(user["role"], -1) < needed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _dep
