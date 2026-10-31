"""B-4: alert on repeated failure. One alert per failure streak (after N consecutive failed runs), one 'recovered'
message when the connector succeeds again. Channels: config-driven actions (Slack webhook, via the action engine),
optional SMTP email, and always a UI banner + log entry."""
from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any

from integration_platform.config import IntegrationConfig, lookup_ref
from integration_platform.db import Database, utcnow
from integration_platform.logmask import mask_text

log = logging.getLogger("alerts")
ERROR_LIMIT = 400  # characters of the last error shown in a chat message


def dashboard_url() -> str:
    """Base URL for links in alert messages (PLATFORM_URL, else this machine's dashboard)."""
    return (os.environ.get("PLATFORM_URL") or f"http://localhost:{os.environ.get('PLATFORM_PORT') or 8000}").rstrip("/")
FAILED = {"error"}
HEALTHY = {"success", "partial", "suspicious"}  # data is flowing again


class FailureAlerter:
    def __init__(self, db: Database, actions: Any):
        self.db = db
        self.actions = actions  # ActionRunner: runs actions whose trigger is connector_failure / connector_recovered

    async def record(self, cfg: IntegrationConfig, result: dict[str, Any]) -> dict[str, Any] | None:
        """Update the failure streak after a run; send at most one alert per streak and one recovery message."""
        status = result.get("status")
        state = self.db.get_failure_state(cfg.name)
        if status in FAILED:
            streak = state["streak"] + 1
            error = mask_text(result.get("error") or "unknown error")
            alerted_at = state["alerted_at"]
            sent = None
            if streak >= cfg.alert_after_failures and not alerted_at:
                alerted_at = utcnow()
                message = f"{cfg.display_name} failed {streak} runs in a row. Last error: {error}"
                sent = await self._send("connector_failure", cfg, message, streak, alerted_at, error)
            self.db.set_failure_state(cfg.name, streak, alerted_at, error)
            return sent
        if status in HEALTHY:
            sent = None
            if state["alerted_at"]:
                message = f"{cfg.display_name} recovered after {state['streak']} failed run(s)."
                sent = await self._send("connector_recovered", cfg, message, state["streak"], state["alerted_at"], None)
            if state["streak"] or state["alerted_at"]:
                self.db.set_failure_state(cfg.name, 0, None, None)
            return sent
        return None  # not_configured / skipped: not a failure, not a recovery

    async def _send(self, trigger: str, cfg: IntegrationConfig, message: str, streak: int, streak_started: str,
                    error: str | None) -> dict[str, Any]:
        channels, failed = ["ui", "log"], []
        short_error = mask_text(error or "")
        if len(short_error) > ERROR_LIMIT:
            short_error = short_error[:ERROR_LIMIT] + "…"
        ctx = {"source": cfg.name, "display_name": cfg.display_name, "trigger": trigger, "streak": streak,
               "streak_started": streak_started, "error": short_error, "message": message, "time": _readable(utcnow()),
               "dashboard_url": dashboard_url(), "id": f"{trigger}-{streak_started}",
               "severity": "high" if trigger == "connector_failure" else "info"}
        for result in await self.actions.notify(trigger, ctx):
            if result.get("status") == "success":
                channels.append(result.get("channel", "action"))
            elif result.get("status") == "failed":  # bounded retries already happened; the claim stops any repeat
                failed.append(f"{result.get('channel')}: {result.get('error')}")
                log.warning("alert channel %s failed: %s", result.get("channel"), result.get("error"))
        if failed:
            message = f"{message} (Alert delivery failed: {'; '.join(failed)})"
        if await asyncio.to_thread(send_email, f"[PlugSec] {message[:120]}", message):
            channels.append("email")
        kind = "failure_alert" if trigger == "connector_failure" else "recovered"
        self.db.add_notification(cfg.name, kind, message, channels)
        (log.error if kind == "failure_alert" else log.info)("ALERT %s: %s (sent to %s)", kind, message, ", ".join(channels))
        return {"kind": kind, "message": message, "channels": channels, "failed": failed}

    async def send_test(self) -> dict[str, Any]:
        """One 'PlugSec: Slack alerts connected' message through every channel subscribed to connector_test."""
        at = utcnow()
        ctx = {"source": "plugsec", "display_name": "PlugSec", "trigger": "connector_test", "streak": 0, "streak_started": at,
               "error": "", "message": "PlugSec: Slack alerts connected", "time": _readable(at), "dashboard_url": dashboard_url(),
               "id": f"connector_test-{at}", "severity": "info"}
        results = await self.actions.notify("connector_test", ctx)
        sent = [r.get("channel") for r in results if r.get("status") == "success"]
        failed = [f"{r.get('channel')}: {r.get('error')}" for r in results if r.get("status") == "failed"]
        missing = [r.get("channel") for r in results if r.get("status") == "not_configured"]
        for f in failed:
            log.warning("test alert failed: %s", f)
        return {"sent": sent, "failed": failed, "not_configured": missing}


def _readable(iso: str) -> str:
    return iso.replace("T", " ").replace("Z", " UTC")


def send_email(subject: str, body: str) -> bool:
    """Optional SMTP channel: only when SMTP_HOST, SMTP_FROM and SMTP_TO are set. Password by name from vault/env."""
    host, sender, to = os.environ.get("SMTP_HOST"), os.environ.get("SMTP_FROM"), os.environ.get("SMTP_TO")
    if not (host and sender and to):
        return False
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, to
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT") or 587), timeout=10) as smtp:
            smtp.starttls()
            user = os.environ.get("SMTP_USER")
            if user:
                smtp.login(user, lookup_ref("SMTP_PASSWORD") or "")
            smtp.send_message(msg)
        return True
    except Exception as exc:  # an alert channel must never break ingestion
        log.warning("SMTP alert failed: %s", mask_text(str(exc)))
        return False
