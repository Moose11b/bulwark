from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt, JWTError
import httpx
import structlog
from sqlalchemy import func
from app.config import get_settings
from app.database import get_db
from app.models import Organisation, User

logger = structlog.get_logger()
settings = get_settings()
bearer = HTTPBearer(auto_error=False)

# JWKS cache keyed by issuer (Clerk frontend-api URL)
_jwks_cache: dict[str, dict] = {}


def _unauthorised(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


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
    """Verify a Clerk-issued JWT against the ONE trusted Clerk issuer.

    The issuer is fixed by configuration (derived from the publishable key),
    never taken from the token. Previously the token's own `iss` chose which
    JWKS to trust, so anyone who ran their own issuer could forge a token for
    any user id and be authenticated as them. The token's `iss` is now only
    accepted if it equals the trusted issuer.
    """
    trusted_issuer = settings.clerk_issuer_url
    if not trusted_issuer:
        raise _unauthorised("Clerk authentication is not configured")

    try:
        unverified = jwt.get_unverified_claims(token)
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        logger.warning("auth.malformed_jwt", error=str(exc))
        raise _unauthorised("Malformed token")

    token_issuer = unverified.get("iss")
    kid = header.get("kid")
    if not token_issuer or not kid:
        raise _unauthorised("Token missing iss or kid")

    if token_issuer.rstrip("/") != trusted_issuer:
        logger.warning(
            "auth.untrusted_issuer",
            token_issuer=token_issuer, trusted=trusted_issuer,
        )
        raise _unauthorised("Token issuer is not trusted")

    try:
        jwks = await _get_jwks(trusted_issuer)
        signing_key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not signing_key:
            # Possibly a rotated key — invalidate cache and retry once.
            _jwks_cache.pop(trusted_issuer, None)
            jwks = await _get_jwks(trusted_issuer)
            signing_key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    except httpx.HTTPError as exc:
        logger.error("auth.jwks_fetch_failed", issuer=trusted_issuer, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to verify token (JWKS fetch failed)",
        )

    if not signing_key:
        raise _unauthorised("Token signing key not found")

    try:
        return jwt.decode(
            token,
            signing_key,
            algorithms=[signing_key.get("alg", "RS256")],
            issuer=trusted_issuer,
            options={"verify_aud": False},  # Clerk JWTs don't always set aud
        )
    except JWTError as exc:
        logger.warning("auth.invalid_jwt", error=str(exc))
        raise _unauthorised("Invalid or expired token")


async def _resolve_oidc_user(db: AsyncSession, claims: dict) -> User:
    """Map verified OIDC claims to a User, provisioning on first login if enabled.

    The external subject is stored in clerk_user_id, namespaced with an `oidc:`
    prefix so it can never collide with a real Clerk id (which starts `user_`).
    Reusing the column avoids a schema change for what is the same concept: an
    opaque external identity.
    """
    subject = claims.get("sub")
    if not subject:
        raise _unauthorised("Token has no subject")
    external_id = f"oidc:{subject}"

    user = (await db.execute(
        select(User).where(User.clerk_user_id == external_id)
    )).scalar_one_or_none()

    if user:
        if not user.is_active:
            raise _unauthorised("User is inactive")
        return user

    if not settings.oidc_auto_provision:
        raise _unauthorised("User is not provisioned")

    # ── Just-in-time provisioning ────────────────────────────────
    org = (await db.execute(
        select(Organisation).where(Organisation.slug == settings.oidc_default_org_slug)
    )).scalar_one_or_none()
    if org is None:
        org = Organisation(
            name=settings.oidc_default_org_name,
            slug=settings.oidc_default_org_slug,
        )
        db.add(org)
        await db.flush()

    # The first user into a fresh org is its admin; later ones get the
    # configured default role.
    existing_count = (await db.execute(
        select(func.count(User.id)).where(User.org_id == org.id)
    )).scalar() or 0
    role = "admin" if existing_count == 0 else settings.oidc_default_role

    user = User(
        clerk_user_id=external_id,
        org_id=org.id,
        email=claims.get("email") or f"{subject}@oidc.local",
        name=claims.get("name") or claims.get("preferred_username"),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("auth.oidc_provisioned", subject=subject, org=org.slug, role=role)
    return user


def _issuer_of(token: str) -> str | None:
    try:
        return (jwt.get_unverified_claims(token).get("iss") or "").rstrip("/") or None
    except JWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise _unauthorised("Authentication required")

    token = credentials.credentials
    token_issuer = _issuer_of(token)

    # Local session token — routed by its fixed issuer, verified with the
    # server secret. Only honoured when local auth is the active mode, so a
    # deployment on Clerk/OIDC can't be presented a locally-forged token.
    from app.core.local_auth import LOCAL_ISSUER
    if token_issuer == LOCAL_ISSUER:
        if settings.effective_auth_mode != "local":
            raise _unauthorised("Local authentication is not enabled")
        from jose import JWTError as _JWTError
        from app.core.local_auth import verify_local_token
        try:
            claims = verify_local_token(token)
        except _JWTError as exc:
            logger.warning("auth.local_invalid", error=str(exc))
            raise _unauthorised("Invalid or expired token")
        user = (await db.execute(
            select(User).where(User.id == claims.get("sub"))
        )).scalar_one_or_none()
        if not user or not user.is_active:
            raise _unauthorised("User not found or inactive")
        return user

    # Route by issuer, but only to issuers this deployment actually trusts.
    # The token cannot select an arbitrary verifier — an unrecognised issuer
    # is rejected rather than fetched from.
    if settings.oidc_enabled and token_issuer == settings.oidc_issuer.rstrip("/"):
        from jose import JWTError as _JWTError
        from app.core.oidc import verify_oidc_token
        try:
            claims = await verify_oidc_token(
                token,
                issuer=settings.oidc_issuer.rstrip("/"),
                audience=settings.oidc_client_id or None,
            )
        except _JWTError as exc:
            logger.warning("auth.oidc_invalid", error=str(exc))
            raise _unauthorised("Invalid or expired token")
        except httpx.HTTPError as exc:
            logger.error("auth.oidc_discovery_failed", error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to verify token (identity provider unreachable)",
            )
        return await _resolve_oidc_user(db, claims)

    # Default to Clerk, which now pins its own trusted issuer internally.
    payload = await _verify_clerk_token(token)
    clerk_user_id = payload.get("sub")
    if not clerk_user_id:
        raise _unauthorised("Invalid token payload")

    user = (await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )).scalar_one_or_none()

    if not user or not user.is_active:
        raise _unauthorised("User not found or inactive")

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
