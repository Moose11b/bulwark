import asyncio
import aiosmtplib
from email.message import EmailMessage
from slack_sdk.web.async_client import AsyncWebhookClient
import httpx
import structlog
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import Finding, Scan, AlertConfig, Organisation
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}

# Lower rank == more severe.
SEV_RANK = {
    s: i for i, s in enumerate(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
    )
}
_UNRANKED = len(SEV_RANK)


async def dispatch_alerts(org_id: str, scan_id: str, finding_ids: list[str]):
    async with AsyncSessionLocal() as db:
        configs_result = await db.execute(
            select(AlertConfig).where(
                AlertConfig.org_id == org_id,
                AlertConfig.is_active == True,
            )
        )
        configs = configs_result.scalars().all()

        if not configs:
            return

        findings_result = await db.execute(
            select(Finding).where(Finding.id.in_(finding_ids))
        )
        findings = findings_result.scalars().all()

        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            return

        for config in configs:
            # Ranking is a dict lookup inside the try, not list.index() outside
            # it: an unrecognised severity previously raised ValueError here and
            # aborted dispatch for every remaining config, not just this one.
            try:
                min_idx = SEV_RANK.get(config.min_severity.value, SEV_RANK["HIGH"])
                relevant = [
                    f for f in findings
                    # Unknown severities rank below everything, so they never
                    # trigger an alert on their own.
                    if SEV_RANK.get(f.severity.value, _UNRANKED) <= min_idx
                ]

                if not relevant:
                    continue

                if config.channel == "slack" and config.webhook_url:
                    await _send_slack(config.webhook_url, scan, relevant)
                elif config.channel == "email" and config.email_to:
                    await _send_email(config.email_to, scan, relevant)
            except Exception as e:
                logger.error("alert.dispatch_failed",
                             config_id=config.id, channel=config.channel, error=str(e))

    logger.info("alerts.dispatched", org_id=org_id, scan_id=scan_id, configs=len(configs))


async def _send_slack(webhook_url: str, scan: "Scan", findings: list["Finding"]):
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ Bulwark — Scan Alert: {scan.target}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Target:*\n{scan.target}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{scan.risk_score:.0f}/100"},
                {"type": "mrkdwn", "text": f"*Scan Type:*\n{scan.scan_type.value.upper()}"},
                {"type": "mrkdwn", "text": f"*Findings:*\n{len(findings)} requiring attention"},
            ],
        },
        {"type": "divider"},
    ]

    for f in findings[:5]:
        emoji = SEV_EMOJI.get(f.severity.value, "⚪")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{f.title}*\n"
                    f"_{f.description[:200] if f.description else ''}_ \n"
                    f"Severity: `{f.severity.value}` | Source: `{f.source}`"
                ),
            },
        })

    if len(findings) > 5:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_... and {len(findings) - 5} more findings_"},
        })

    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(webhook_url, json={"blocks": blocks})

    logger.info("alert.slack_sent", target=scan.target, findings=len(findings))


async def _send_email(to_email: str, scan: "Scan", findings: list["Finding"]):
    if not settings.smtp_user:
        logger.warning("alert.email_skipped", reason="SMTP not configured")
        return

    rows = "\n".join(
        f"  [{f.severity.value}] {f.title}"
        for f in findings[:10]
    )
    if len(findings) > 10:
        rows += f"\n  ... and {len(findings) - 10} more"

    msg = EmailMessage()
    msg["Subject"] = f"[Bulwark] Scan Alert — {scan.target} ({len(findings)} findings)"
    msg["From"]    = settings.smtp_from
    msg["To"]      = to_email
    msg.set_content(
        f"Bulwark Security Alert\n"
        f"{'='*50}\n\n"
        f"Target:     {scan.target}\n"
        f"Scan type:  {scan.scan_type.value.upper()}\n"
        f"Risk score: {scan.risk_score:.0f}/100\n\n"
        f"Findings requiring attention:\n{rows}\n\n"
        f"Log in to Bulwark to view full details and start remediation.\n\n"
        f"Fortify · Detect · Defend\n"
        f"The Bulwark Team\n"
    )

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )
        logger.info("alert.email_sent", to=to_email, findings=len(findings))
    except Exception as e:
        logger.error("alert.email_failed", error=str(e))
