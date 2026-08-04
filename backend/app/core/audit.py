"""
Audit logging + output sanitisation helpers.

audit_log() writes an immutable record of security-relevant actions
(scan launched, finding status changed, role changed, billing event).

sanitize() strips control characters and caps length on any string that
originated from scanner output before it is stored or rendered, preventing
stored-XSS / log-injection from a malicious scan target's banners.
"""
import re
import structlog
from datetime import datetime

logger = structlog.get_logger()

# Control chars except tab/newline/carriage-return
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Anything that looks like an HTML tag or script handler
_HTML_TAG = re.compile(r"<[^>]*>")
_JS_SCHEME = re.compile(r"javascript:", re.IGNORECASE)


def sanitize(value: str | None, max_len: int = 4000) -> str | None:
    """Clean a string that came from untrusted scanner output."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    # Drop control characters
    value = _CONTROL_CHARS.sub("", value)
    # Neutralise HTML tags and javascript: URIs (defence in depth — the
    # frontend also escapes, but we never want raw markup in the DB)
    value = _HTML_TAG.sub("", value)
    value = _JS_SCHEME.sub("", value)
    # Cap length
    if len(value) > max_len:
        value = value[:max_len] + "…"
    return value.strip()


def sanitize_finding(finding: dict) -> dict:
    """Sanitise all free-text fields of a finding dict in place."""
    text_fields = ("title", "description", "evidence", "remediation", "raw_output")
    for field in text_fields:
        if field in finding and finding[field] is not None:
            finding[field] = sanitize(finding[field])
    return finding


async def audit_log(
    db,
    *,
    org_id: str,
    action: str,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Write an audit log entry. Never raises — auditing must not break flows."""
    from app.models import AuditLog
    try:
        entry = AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail or {},
            ip_address=ip_address,
        )
        db.add(entry)
        await db.flush()
    except Exception as e:
        logger.warning("audit.write_failed", action=action, error=str(e))
