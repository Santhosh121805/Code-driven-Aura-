"""Deterministic demo controls against the real connectors.

Nothing here fakes a tool: "network off" and "repeated failure" run a real connector once against an address nothing
listens on, and "wrong key" calls the real GitHub API with an obviously invalid token.
"""
from __future__ import annotations

import os
from typing import Any

from integration_platform.config import AuthBearer
from integration_platform.scheduler import Registry

DEFAULT_CONNECTOR = "github"
DEAD_ADDRESS = "http://127.0.0.1:9"  # discard port: nothing listens, so every call is a real connection error


class DemoError(Exception):
    pass


def _require_active(registry: Registry, name: str) -> None:
    cfg = registry.integrations.get(name)
    if cfg is None:
        raise DemoError(f"Integration '{name}' is not configured")
    if not cfg.enabled:
        raise DemoError(f"{cfg.display_name} is paused or disabled - resume it (or reset the demo) first")


async def network_off(registry: Registry, name: str = DEFAULT_CONNECTOR) -> dict[str, Any]:
    """'Network off mid-run': one run of this connector against an address nothing listens on. Real connection
    errors -> retries at 1s, 2s, 4s -> the run is recorded as FAILED on the connector's health card."""
    _require_active(registry, name)
    cfg = registry.integrations[name]
    dead = cfg.model_copy(update={"base_url": DEAD_ADDRESS, "retry": cfg.retry.model_copy(update={"max_retries": 3, "base_seconds": 1})})
    return await registry.run_now(name, wait=True, cfg_override=dead)


async def repeated_failure(registry: Registry, name: str = DEFAULT_CONNECTOR) -> dict[str, Any]:
    """B-4: N consecutive failed runs (dead address, no retries so it is quick) -> one alert; then one good run -> recovered."""
    _require_active(registry, name)
    cfg = registry.integrations[name]
    dead = cfg.model_copy(update={"base_url": DEAD_ADDRESS, "retry": cfg.retry.model_copy(update={"max_retries": 0})})
    runs = [await registry.run_now(name, wait=True, cfg_override=dead) for _ in range(cfg.alert_after_failures)]
    recovered = await registry.run_now(name, wait=True)
    return {"status": "done", "failed_runs": len(runs), "threshold": cfg.alert_after_failures,
            "alerts": [r.get("alert") for r in runs if r.get("alert")], "recovery": recovered.get("alert"),
            "recovery_run": recovered.get("status")}


INVALID_DEMO_TOKEN = "github_pat_INVALID_demo_token_not_a_real_secret"


async def wrong_key(registry: Registry) -> dict[str, Any]:
    """Call the REAL GitHub API with a deliberately invalid token: a real 401, shown as 'Authentication failed', no retries.
    Nothing is stored."""
    from integration_platform.engine import AuthError, EngineError, Stats, fetch_records
    gh = registry.integrations.get("github")
    if gh is None:
        raise DemoError("The wrong-key demo needs the GitHub integration")
    os.environ["DEMO_INVALID_TOKEN"] = INVALID_DEMO_TOKEN  # obviously fake; never a real secret
    cfg = gh.model_copy(update={"auth": AuthBearer(type="bearer", token="${DEMO_INVALID_TOKEN}"), "streams": [gh.stream("me")]})
    stats = Stats()
    try:
        await fetch_records(cfg, cfg.streams[0], transport=registry.transport, stats=stats)
    except AuthError as exc:
        return {"status": "auth_failed", "target": cfg.base_url, "http_status": exc.status, "retries": stats.retries, "error": str(exc)}
    except EngineError as exc:
        raise DemoError(f"GitHub is unreachable: {exc}")
    return {"status": "unexpected_success", "target": cfg.base_url}
