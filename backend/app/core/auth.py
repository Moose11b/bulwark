from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt, JWTError
import httpx
import structlog
from app.config import get_settings
from app.database import get_db
from app.models import Organisation, User

logger = structlog.get_logger()
settings = get_settings()
bearer = HTTPBearer(auto_error=False)

# JWKS cache keyed by issuer (Clerk frontend-api URL)
_jwks_cache: dict[str, dict] = {}


async def _get_jwks(issuer: str) -> dict:
    """Fetch and cache JWKS for a Clerk issuer."""
    if issuer in _jwks_cache:
        return _jwks_cache[issuer]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{issuer.rstrip('/')}/.well-known/jwks.json")
        resp.raise_for_status()
        _jwks_cache[issuer] = resp.json()
    return _jwks_cache[issuer]


async def _verify_clerk_token(token: str) -> dict:
    """Verify a Clerk-issued JWT locally using the issuer's JWKS."""
    try:
        unverified = jwt.get_unverified_claims(token)
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        logger.warning("auth.malformed_jwt", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    issuer = unverified.get("iss")
    kid = header.get("kid")
    if not issuer or not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing iss or kid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        jwks = await _get_jwks(issuer)
    except httpx.HTTPError as exc:
        logger.error("auth.jwks_fetch_failed", issuer=issuer, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to verify token (JWKS fetch failed)",
        )

    signing_key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if not signing_key:
        # Possibly a rotated key — invalidate cache and retry once
        _jwks_cache.pop(issuer, None)
        jwks = await _get_jwks(issuer)
        signing_key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if not signing_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signing key not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=[signing_key.get("alg", "RS256")],
            issuer=issuer,
            options={"verify_aud": False},  # Clerk JWTs don't always set aud
        )
        return payload
    except JWTError as exc:
        logger.warning("auth.invalid_jwt", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = await _verify_clerk_token(credentials.credentials)
    clerk_user_id = payload.get("sub")

    if not clerk_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


async def get_current_org(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Organisation:
    result = await db.execute(
        select(Organisation).where(Organisation.id == user.org_id)
    )
    org = result.scalar_one_or_none()

    if not org or not org.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organisation not found or inactive",
        )

    return org


def require_role(*roles: str):
    """Dependency factory — require the current user to have one of the given roles."""
    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not authorised for this action",
            )
        return user
    return _check


require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")
