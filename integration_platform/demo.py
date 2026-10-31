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


# ---------------------------------------------------------------- controls that need the Demo source (Mock)
def _require_mock(registry: Registry) -> str:
    """The mock is disabled on purpose (it only runs from here), but a paused or revoked one is not silently re-run."""
    from integration_platform import demo_mock
    if demo_mock.NAME not in registry.integrations:
        raise DemoError("The Demo source (Mock) is not configured (configs/integrations/demo_mock.yaml)")
    state = registry.db.get_state(demo_mock.NAME)
    if state and state["state"] in ("suspicious", "revoked"):
        raise DemoError(f"Demo source (Mock) is {state['state']}: resume it (or reset the demo) first")
    return demo_mock.NAME


async def trigger_429(registry: Registry) -> dict[str, Any]:
    """Exactly two HTTP 429s on the next run of the mock, then success: 'Recovered after 2 retries'."""
    from integration_platform import demo_mock
    name = _require_mock(registry)
    return await registry.run_now(name, wait=True, prepare=lambda: _arm(demo_mock.arm, "rate_limit", count=2, retry_after=1))


async def trigger_retry_after(registry: Registry, seconds: int = 5) -> dict[str, Any]:
    """One HTTP 429 with Retry-After: 5: the run visibly waits 5 s, then succeeds."""
    from integration_platform import demo_mock
    name = _require_mock(registry)
    return await registry.run_now(name, wait=True, prepare=lambda: _arm(demo_mock.arm, "rate_limit", count=1, retry_after=seconds))


async def trigger_malformed(registry: Registry) -> dict[str, Any]:
    """One record with an unparseable time in the next response: it is quarantined and the run continues."""
    from integration_platform import demo_mock
    name = _require_mock(registry)
    return await registry.run_now(name, wait=True, prepare=lambda: _arm(demo_mock.arm, "malformed"))


async def simulate_bulk_export(registry: Registry, multiplier: int = 50) -> dict[str, Any]:
    """Next page returns ~50x normal volume, as a stolen token doing a bulk export would: the exfiltration guard
    pauses the mock and raises a critical alert (which opens a ticket). Warms the baseline with normal runs first."""
    from integration_platform import demo_mock
    name = _require_mock(registry)
    guard = registry.integrations[name].exfiltration_guard
    warmed = 0
    while len(registry.db.baseline_counts(name, guard.baseline_runs)) < guard.min_baseline_runs and warmed < guard.min_baseline_runs + 3:
        await registry.run_now(name, wait=True)
        warmed += 1
    result = await registry.run_now(name, wait=True, prepare=lambda: _arm(demo_mock.arm, "bulk", multiplier=multiplier))
    return {**result, "baseline_warmup_runs": warmed}


async def _arm(fn, kind: str, **detail: Any) -> None:
    fn(kind, **detail)
