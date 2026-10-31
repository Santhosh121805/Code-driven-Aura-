"""Deterministic demo controls: arm a one-shot fault on a mock tool, then run the connector immediately.

The fault is armed *inside* the connector's run lock, so a scheduled run can never consume it first.
These only talk to the mocks' /__demo/* endpoints; real tools have no such endpoints.
"""
from __future__ import annotations

from typing import Any

import os

import httpx

from integration_platform.config import AuthBearer
from integration_platform.scheduler import Registry


class DemoError(Exception):
    pass


async def _control(registry: Registry, name: str, path: str, **params: Any) -> dict[str, Any]:
    cfg = registry.integrations[name]
    async with httpx.AsyncClient(timeout=5, transport=registry.transport) as client:
        resp = await client.post(f"{cfg.base_url}/__demo/{path}", params=params)
        resp.raise_for_status()
        return resp.json()


def _require_active(registry: Registry, name: str) -> None:
    cfg = registry.integrations.get(name)
    if cfg is None:
        raise DemoError(f"Integration '{name}' is not configured")
    if not cfg.enabled:
        raise DemoError(f"{cfg.display_name} is paused or disabled - resume it (or reset the demo) first")


async def trigger_429(registry: Registry, name: str = "acme_firewall") -> dict[str, Any]:
    """Exactly two HTTP 429s on the next run, then success: the run shows 'Recovered after 2 retries'."""
    _require_active(registry, name)
    return await registry.run_now(name, wait=True, prepare=lambda: _control(registry, name, "rate-limit-next", count=2))


async def trigger_retry_after(registry: Registry, name: str = "acme_firewall", seconds: int = 5) -> dict[str, Any]:
    """One HTTP 429 with Retry-After: 5 - the run visibly waits 5 s, then succeeds."""
    _require_active(registry, name)
    return await registry.run_now(name, wait=True, prepare=lambda: _control(registry, name, "rate-limit-next", count=1, retry_after=seconds))


async def network_off(registry: Registry, name: str = "acme_firewall") -> dict[str, Any]:
    """'Network off mid-run': one run of this connector against an address nothing listens on. Real connection
    errors -> retries at 1s, 2s, 4s -> the run is recorded as FAILED on the connector's health card."""
    _require_active(registry, name)
    cfg = registry.integrations[name]
    dead = cfg.model_copy(update={"base_url": "http://127.0.0.1:9", "retry": cfg.retry.model_copy(update={"max_retries": 3, "base_seconds": 1})})
    return await registry.run_now(name, wait=True, cfg_override=dead)


async def repeated_failure(registry: Registry, name: str = "acme_firewall") -> dict[str, Any]:
    """B-4: N consecutive failed runs (dead address, no retries so it is quick) -> one alert; then one good run -> recovered."""
    _require_active(registry, name)
    cfg = registry.integrations[name]
    dead = cfg.model_copy(update={"base_url": "http://127.0.0.1:9", "retry": cfg.retry.model_copy(update={"max_retries": 0})})
    runs = [await registry.run_now(name, wait=True, cfg_override=dead) for _ in range(cfg.alert_after_failures)]
    recovered = await registry.run_now(name, wait=True)
    return {"status": "done", "failed_runs": len(runs), "threshold": cfg.alert_after_failures,
            "alerts": [r.get("alert") for r in runs if r.get("alert")], "recovery": recovered.get("alert"),
            "recovery_run": recovered.get("status")}


INVALID_DEMO_TOKEN = "github_pat_INVALID_demo_token_not_a_real_secret"


async def wrong_key(registry: Registry) -> dict[str, Any]:
    """Call the REAL GitHub API with a deliberately invalid token: a real 401, shown as 'Authentication failed', no retries.
    Nothing is stored. Falls back to the firewall mock with a wrong key when GitHub is unreachable (offline demo)."""
    from integration_platform.engine import AuthError, EngineError, Stats, fetch_records
    os.environ["DEMO_INVALID_TOKEN"] = INVALID_DEMO_TOKEN  # obviously fake; never a real secret
    gh = registry.integrations.get("github")
    targets = []
    if gh:
        targets.append(gh.model_copy(update={"auth": AuthBearer(type="bearer", token="${DEMO_INVALID_TOKEN}"),
                                             "streams": [gh.stream("me")]}))
    fw = registry.integrations.get("acme_firewall")
    if fw:
        targets.append(fw.model_copy(update={"auth": fw.auth.model_copy(update={"api_key": "${DEMO_INVALID_TOKEN}"}),
                                             "streams": [fw.streams[0]]}))
    for cfg in targets:
        stats = Stats()
        try:
            await fetch_records(cfg, cfg.streams[0], transport=registry.transport, stats=stats)
            return {"status": "unexpected_success", "target": cfg.base_url}
        except AuthError as exc:
            return {"status": "auth_failed", "target": cfg.base_url, "http_status": exc.status, "retries": stats.retries, "error": str(exc)}
        except EngineError:
            continue  # unreachable (offline): try the next target
    raise DemoError("No target reachable for the wrong-key demo")


async def trigger_malformed(registry: Registry, name: str = "acme_firewall", kind: str = "bad_time") -> dict[str, Any]:
    """One malformed record in the next response: it is quarantined and the run continues."""
    _require_active(registry, name)
    return await registry.run_now(name, wait=True, prepare=lambda: _control(registry, name, "malformed-next", kind=kind))


async def simulate_bulk_export(registry: Registry, name: str = "aws_cloudtrail", multiplier: int = 20) -> dict[str, Any]:
    """Next page returns ~20x normal volume, as a stolen token doing a bulk export would. Warms the guard's
    baseline with normal runs first if this connector has not run often enough yet."""
    _require_active(registry, name)
    guard = registry.integrations[name].exfiltration_guard
    warmed = 0
    while len(registry.db.baseline_counts(name, guard.baseline_runs)) < guard.min_baseline_runs and warmed < guard.min_baseline_runs + 3:
        await registry.run_now(name, wait=True)
        warmed += 1
    result = await registry.run_now(name, wait=True, prepare=lambda: _control(registry, name, "bulk-export-next", multiplier=multiplier))
    return {**result, "baseline_warmup_runs": warmed}


async def reset_mocks(registry: Registry) -> None:
    """Disarm any pending one-shot faults (best effort)."""
    for name, cfg in list(registry.integrations.items()):
        if not cfg.base_url.startswith(("http://localhost", "http://127.0.0.1")):
            continue  # never send demo-control calls to real APIs
        try:
            await _control(registry, name, "reset")
        except Exception:
            pass
