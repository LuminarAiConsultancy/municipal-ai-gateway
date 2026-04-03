"""Webhook and email alerts for the Canadian Municipal AI Gateway.

Sends alerts on:
  - PII spike (many detections in a single request)
  - Budget threshold (80% of monthly limit reached)
  - Audit chain failure

Both webhook and email are optional — the gateway works without either.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText

import httpx

from logging_config import get_logger

logger = get_logger("alerts")

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_FROM = os.getenv("SMTP_FROM", "gateway@localhost")

PII_SPIKE_THRESHOLD = int(os.getenv("PII_SPIKE_THRESHOLD", "10"))


async def send_alert(*, event: str, message: str, details: dict | None = None):
    """Send an alert via configured channels (webhook and/or email)."""
    payload = {
        "event": event,
        "message": message,
        "details": details or {},
    }

    if ALERT_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(ALERT_WEBHOOK_URL, json=payload)
            logger.info("alert_webhook_sent", event=event)
        except Exception as e:
            logger.error("alert_webhook_failed", event=event, error=str(e))

    if ALERT_EMAIL:
        try:
            body = f"{message}\n\nDetails:\n{json.dumps(details or {}, indent=2)}"
            msg = MIMEText(body)
            msg["Subject"] = f"[AI Gateway Alert] {event}"
            msg["From"] = SMTP_FROM
            msg["To"] = ALERT_EMAIL
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                smtp.send_message(msg)
            logger.info("alert_email_sent", event=event, to=ALERT_EMAIL)
        except Exception as e:
            logger.error("alert_email_failed", event=event, error=str(e))


async def check_pii_spike(*, pii_count: int, department: str, provider: str):
    """Alert if PII detections exceed the spike threshold."""
    if pii_count >= PII_SPIKE_THRESHOLD:
        await send_alert(
            event="pii_spike",
            message=f"High PII detection count ({pii_count}) in {department} request to {provider}",
            details={"pii_count": pii_count, "department": department, "provider": provider},
        )


async def check_budget_threshold(
    *, department: str, used_cents: int, limit_cents: int
):
    """Alert when budget usage exceeds 80% of the monthly limit."""
    if limit_cents and used_cents >= limit_cents * 0.8:
        pct = round(used_cents / limit_cents * 100, 1)
        await send_alert(
            event="budget_warning",
            message=f"Department '{department}' at {pct}% of monthly budget",
            details={
                "department": department,
                "used_cents": used_cents,
                "limit_cents": limit_cents,
                "percentage": pct,
            },
        )


async def alert_chain_failure(*, entry_id: int, message: str):
    """Alert on audit chain integrity failure."""
    await send_alert(
        event="chain_failure",
        message=f"Audit chain integrity failure at entry {entry_id}",
        details={"entry_id": entry_id, "detail": message},
    )
