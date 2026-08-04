from fastapi import APIRouter, Depends

from app.core.auth import get_current_org, get_current_user
from app.models import Organisation, User

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "auth", "status": "ok"}


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
        },
        "org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "plan": org.plan.value if hasattr(org.plan, "value") else org.plan,
            "scan_count_month": org.scan_count_month,
            "scan_limit": org.scan_limit,
        },
    }
