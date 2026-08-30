import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.auth import get_current_org, get_current_user
from app.core.local_auth import (
    create_local_token,
    hash_password,
    password_problems,
    verify_password,
)
from app.database import get_db
from app.models import Organisation, User

router = APIRouter()
logger = structlog.get_logger()
settings = get_settings()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=1)


def _require_local_mode():
    if settings.effective_auth_mode != "local":
        # 404 rather than 403: when local auth is off, the endpoint may as well
        # not exist, and this avoids hinting at its presence.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Local authentication is not enabled",
        )


@router.get("/config")
async def auth_config():
    """Public: lets the frontend render the right sign-in UI at runtime."""
    return {"auth_mode": settings.effective_auth_mode}


@router.get("/health")
async def health():
    return {"module": "auth", "status": "ok"}


@router.post("/login")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Local email/password login. Returns a signed session token.

    The same generic error is returned whether the email is unknown or the
    password is wrong, so the endpoint can't be used to enumerate accounts.
    """
    _require_local_mode()
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
    )

    user = (await db.execute(
        select(User).where(User.email == body.email.lower())
    )).scalar_one_or_none()

    # Always run a verify so the response time doesn't reveal whether the email
    # exists (a dummy hash when the user is absent).
    stored = user.password_hash if (user and user.password_hash) else (
        "$2b$12$" + "." * 53
    )
    ok = verify_password(body.password, stored)
    if not user or not user.password_hash or not ok:
        logger.info("auth.local_login_failed", email=body.email)
        raise invalid
    if not user.is_active:
        raise invalid

    token = create_local_token(user.id, user.role, user.email)
    logger.info("auth.local_login", user=user.id, email=user.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "must_change_password": user.must_change_password,
        "user": {"id": user.id, "email": user.email, "name": user.name,
                 "role": user.role},
    }


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's local password (also clears the forced-change
    flag set on the bootstrap admin)."""
    _require_local_mode()
    if not user.password_hash or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password " + "; ".join(problems),
        )
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    await db.commit()
    logger.info("auth.password_changed", user=user.id)
    return {"status": "ok"}


@router.get("/me")
async def whoami(
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    return {
        "user": {
            "id": user.id,
            "clerk_user_id": user.clerk_user_id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "is_active": user.is_active,
            "must_change_password": user.must_change_password,
        },
        "auth_mode": settings.effective_auth_mode,
        "org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "plan": org.plan.value if hasattr(org.plan, "value") else org.plan,
            "scan_count_month": org.scan_count_month,
            "scan_limit": org.scan_limit,
        },
    }
