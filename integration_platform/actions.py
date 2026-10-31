"""Config-driven outbound actions (e.g. create a Jira ticket for high/critical alerts)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx
import jmespath
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

from integration_platform.config import ActionConfig, MissingSecretError, load_action_files, resolve_env
from integration_platform.db import Database
from integration_platform.engine import EngineError, Sleep, Stats, apply_auth, check_response, send_with_retry
from integration_platform.logmask import mask_text

log = logging.getLogger("actions")


def _json_safe(value: Any) -> Any:
    """Escape interpolated values so they are safe inside a JSON string literal in body_template."""
    if value is None:
        return ""
    if isinstance(value, Markup):  # output of |tojson etc. is already JSON
        return value
    return json.dumps(str(value))[1:-1]


_body_env = SandboxedEnvironment(finalize=_json_safe)
_text_env = SandboxedEnvironment(finalize=lambda v: "" if v is None else v)
CONTEXT_FIELDS = ("source", "stream", "id", "type", "severity", "timestamp", "description", "host", "src_ip", "dst_ip", "user", "fetched_at")


class ActionRunner:
    def __init__(self, db: Database, transport: httpx.AsyncBaseTransport | None = None, sleep: Sleep = asyncio.sleep):
        self.db = db
        self.transport = transport
        self.sleep = sleep
        self.actions: dict[str, ActionConfig] = {}
        self.load_errors: dict[str, list[str]] = {}
        self.reload()

    def reload(self) -> None:
        self.actions, self.load_errors = load_action_files()

    @staticmethod
    def matches(action: ActionConfig, event: dict[str, Any]) -> bool:
        when = action.when
        if when.severity_in is not None and event.get("severity") not in when.severity_in:
            return False
        if when.source_in is not None and event.get("source") not in when.source_in:
            return False
        return True

    async def handle(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Called for each newly stored event."""
        return [await self.fire(a, event) for a in list(self.actions.values())
                if a.enabled and "event" in a.trigger and self.matches(a, event)]

    async def notify(self, trigger: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """B-4: run the actions subscribed to a connector_failure / connector_recovered trigger."""
        results = []
        for a in list(self.actions.values()):
            if a.enabled and trigger in a.trigger and (a.when.source_in is None or ctx.get("source") in a.when.source_in):
                results.append({**await self.fire(a, ctx), "channel": a.name})
        return results

    async def fire(self, action: ActionConfig, event: dict[str, Any]) -> dict[str, Any]:
        ctx = {**{k: None for k in CONTEXT_FIELDS}, **{k: v for k, v in event.items() if k != "raw"}, "raw": event.get("raw")}
        try:
            target = resolve_env(action.request.base_url).rstrip("/") + action.request.endpoint
        except MissingSecretError as exc:  # e.g. SLACK_WEBHOOK_URL not set: channel simply not configured
            return {"status": "not_configured", "error": str(exc)}
        dedupe_key = _text_env.from_string(action.dedupe_key).render(**ctx)
        # Claim first: the UNIQUE (action, dedupe_key) row guarantees one ticket per event even under concurrency.
        # A failed attempt keeps its claim, so a flaky response can never lead to a second ticket.
        if not self.db.claim_dedupe(action.name, dedupe_key):
            return {"status": "duplicate", "dedupe_key": dedupe_key}
        stats = Stats()
        try:
            rendered = _body_env.from_string(action.body_template).render(**ctx)
            try:
                body = json.loads(rendered)
            except json.JSONDecodeError as exc:
                raise EngineError(f"body_template did not render valid JSON ({exc.msg} at char {exc.pos})")
            req = action.request
            url = target
            async with httpx.AsyncClient(timeout=req.timeout_seconds, transport=self.transport) as client:
                headers, auth = await apply_auth(client, req.auth, req.base_url, action.retry, stats, self.sleep)
                headers.update(req.headers)
                resp = await send_with_retry(client, req.method, url, action.retry, stats, self.sleep, json=body, headers=headers, auth=auth)
                hint = "Check the action's credentials in .env."
                if action.response_ticket_path:
                    data = check_response(resp, hint)
                else:  # e.g. a Slack webhook answers plain text "ok": only the status matters
                    if resp.status_code >= 400:
                        check_response(resp, hint)  # raises a clear (masked) error
                    data = None
            ticket = jmespath.search(action.response_ticket_path, data) if action.response_ticket_path else None
            ticket = str(ticket) if ticket is not None else None
            self.db.complete_dedupe(action.name, dedupe_key, ticket)
            self.db.add_action_result(action.name, dedupe_key, event["source"], event["id"], "success", ticket, None, stats.retries + 1)
            if ticket:
                self.db.set_event_ticket(event["source"], event["id"], ticket)
            return {"status": "success", "ticket_key": ticket, "dedupe_key": dedupe_key}
        except Exception as exc:
            error = mask_text(str(exc) if isinstance(exc, EngineError) else f"{type(exc).__name__}: {exc}")
            log.warning("action %s failed for %s: %s", action.name, dedupe_key, error)
            self.db.add_action_result(action.name, dedupe_key, event["source"], event["id"], "failed", None, error, stats.retries + 1)
            return {"status": "failed", "error": error, "dedupe_key": dedupe_key}
