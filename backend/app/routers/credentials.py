"""
Scan credential management.

Write-only by design. A stored credential can be set, replaced, or deleted,
but never read back — not by the UI, not by an admin, not through any
response. Bulwark needs it to replay a request; nobody needs it returned.
That removes a whole class of exposure: a compromised session or an
over-permissive role cannot exfiltrate what the API will not emit.
"""
import re
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import audit_log
from app.core.auth import get_current_org, require_analyst
from app.core.secrets import (
    CredentialEncryptionUnavailable,
    encrypt_secret,
    encryption_available,
)
from app.database import get_db
from app.models import Asset, AssetCredential, AuthType, Organisation, User

logger = structlog.get_logger()
router = APIRouter()

# Header names a credential may be sent under. Restricting this stops a
# credential being aimed at a header with side effects (Host, Cookie
# smuggling, proxy control headers).
_ALLOWED_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{0,62}$")
_FORBIDDEN_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "upgrade", "proxy-authorization", "x-forwarded-for", "x-forwarded-host",
}


class CredentialIn(BaseModel):
    auth_type: AuthType
    secret: str = Field(min_length=1, max_length=8192)
    header_name: str | None = Field(default=None, max_length=64)

    @field_validator("secret")
    @classmethod
    def _no_control_characters(cls, v: str) -> str:
        # A newline in a header value is request splitting.
        if any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValueError("Secret must not contain control characters.")
        return v

    @field_validator("header_name")
    @classmethod
    def _safe_header(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _ALLOWED_HEADER.match(v):
            raise ValueError("Header name contains invalid characters.")
        if v.lower() in _FORBIDDEN_HEADERS:
            raise ValueError(f"'{v}' may not be used as a credential header.")
        return v


class CredentialStatus(BaseModel):
    """Everything the API will disclose: that one exists, not what it is."""
    configured: bool
    auth_type: str | None = None
    header_name: str | None = None
    updated_at: datetime | None = None
    last_used_at: datetime | None = None


@router.get("/health")
async def health():
    return {"module": "credentials", "status": "ok"}


async def _get_asset(db: AsyncSession, asset_id: str, org: Organisation) -> Asset:
    asset = (await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org.id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/assets/{asset_id}/credential", response_model=CredentialStatus)
async def get_credential_status(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    await _get_asset(db, asset_id, org)
    record = (await db.execute(
        select(AssetCredential).where(AssetCredential.asset_id == asset_id)
    )).scalar_one_or_none()

    if not record:
        return CredentialStatus(configured=False)
    return CredentialStatus(
        configured=True,
        auth_type=record.auth_type.value,
        header_name=record.header_name,
        updated_at=record.updated_at,
        last_used_at=record.last_used_at,
    )


@router.put("/assets/{asset_id}/credential", response_model=CredentialStatus)
async def set_credential(
    asset_id: str,
    body: CredentialIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    if not encryption_available():
        # Refuse rather than store in cleartext.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Scan credentials are disabled: CREDENTIAL_ENCRYPTION_KEY is not "
                "configured on the server."
            ),
        )

    asset = await _get_asset(db, asset_id, org)

    if body.auth_type == AuthType.HEADER and not body.header_name:
        raise HTTPException(400, "header_name is required for auth_type 'header'.")

    try:
        ciphertext = encrypt_secret(body.secret)
    except CredentialEncryptionUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    record = (await db.execute(
        select(AssetCredential).where(AssetCredential.asset_id == asset_id)
    )).scalar_one_or_none()

    if record:
        record.auth_type = body.auth_type
        record.header_name = body.header_name
        record.secret_encrypted = ciphertext
        record.updated_at = datetime.utcnow()
        action = "credential.updated"
    else:
        record = AssetCredential(
            asset_id=asset.id,
            org_id=org.id,
            auth_type=body.auth_type,
            header_name=body.header_name,
            secret_encrypted=ciphertext,
            created_by_id=user.id,
        )
        db.add(record)
        action = "credential.created"

    # Audit records that a credential changed, never any part of its value.
    await audit_log(
        db, org_id=org.id, user_id=user.id, action=action,
        resource_type="asset", resource_id=asset.id,
        detail={"auth_type": body.auth_type.value},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(record)

    logger.info("credential.set", asset_id=asset.id, auth_type=body.auth_type.value)
    return CredentialStatus(
        configured=True,
        auth_type=record.auth_type.value,
        header_name=record.header_name,
        updated_at=record.updated_at,
        last_used_at=record.last_used_at,
    )


@router.delete("/assets/{asset_id}/credential", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    asset_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    await _get_asset(db, asset_id, org)
    record = (await db.execute(
        select(AssetCredential).where(AssetCredential.asset_id == asset_id)
    )).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="No credential configured")

    await db.delete(record)
    await audit_log(
        db, org_id=org.id, user_id=user.id, action="credential.deleted",
        resource_type="asset", resource_id=asset_id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
