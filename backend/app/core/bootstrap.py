"""
First-run bootstrap for local authentication.

When the platform starts in local auth mode with an empty user table, it
creates an initial admin so the operator can log in immediately — the same
first-run experience as Grafana, Gitea, or Portainer. The password comes from
BOOTSTRAP_ADMIN_PASSWORD if set, otherwise a strong random one is generated and
logged once; either way, a generated password forces a change on first login.

Idempotent and safe to call on every startup: it does nothing once any user
exists.
"""
import secrets

import structlog
from sqlalchemy import func, select

from app.config import get_settings
from app.core.local_auth import hash_password
from app.database import AsyncSessionLocal
from app.models import Organisation, User

logger = structlog.get_logger()

_DEFAULT_ORG_SLUG = "default"
_DEFAULT_ORG_NAME = "Default Organisation"


async def ensure_bootstrap_admin() -> None:
    settings = get_settings()
    if settings.effective_auth_mode != "local":
        return

    async with AsyncSessionLocal() as db:
        user_count = (await db.execute(select(func.count(User.id)))).scalar() or 0
        if user_count > 0:
            return  # already provisioned — nothing to do

        email = (settings.bootstrap_admin_email or "admin@bulwark.local").lower()

        explicit = bool(settings.bootstrap_admin_password)
        password = settings.bootstrap_admin_password or secrets.token_urlsafe(16)

        org = (await db.execute(
            select(Organisation).where(Organisation.slug == _DEFAULT_ORG_SLUG)
        )).scalar_one_or_none()
        if org is None:
            org = Organisation(name=_DEFAULT_ORG_NAME, slug=_DEFAULT_ORG_SLUG)
            db.add(org)
            await db.flush()

        admin = User(
            clerk_user_id=f"local:{email}",   # reuse the external-id column
            org_id=org.id,
            email=email,
            name="Administrator",
            role="admin",
            password_hash=hash_password(password),
            # A generated password must be changed; an explicitly-set one is
            # taken as deliberate.
            must_change_password=not explicit,
        )
        db.add(admin)
        await db.commit()

        if explicit:
            logger.info("bootstrap.admin_created", email=email,
                        detail="Initial admin created with the configured password.")
        else:
            # Logged once, prominently. This is the only time the generated
            # password is shown; it is never stored in plaintext.
            logger.warning(
                "bootstrap.admin_created",
                email=email,
                generated_password=password,
                detail="Initial admin created. Log in with this one-time "
                       "password and change it immediately.",
            )
