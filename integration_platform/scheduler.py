"""Integration registry + APScheduler: runs each enabled integration every schedule_seconds, hot-loads configs."""
from __future__ import annotations

import asyncio
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from integration_platform.actions import ActionRunner
from integration_platform.config import (
    ACTIONS_DIR, INTEGRATIONS_DIR, IntegrationConfig, load_integration_files, missing_settings, save_integration_file,
)
from integration_platform.db import Database
from integration_platform.engine import clear_oauth_cache, run_integration
from integration_platform.vault import Vault, secret_refs

log = logging.getLogger("scheduler")
SEEDED_INTEGRATIONS = ("aws_cloudtrail", "acme_firewall", "mock_okta", "github", "okta", "jira", "nvd")


class Registry:
    def __init__(self, db: Database, actions: ActionRunner, vault: Vault | None = None, alerter: Any = None):
        self.db = db
        self.actions = actions
        self.vault = vault
        self.alerter = alerter  # B-4 FailureAlerter (optional)
        self.transport = None  # tests inject an httpx transport
        self.sleep = asyncio.sleep  # ...and an instant sleep
        self.integrations: dict[str, IntegrationConfig] = {}
        self.load_errors: dict[str, list[str]] = {}
        self.scheduler = AsyncIOScheduler(timezone=timezone.utc)
        self._locks: dict[str, asyncio.Lock] = {}
        self._mtimes: dict[str, float] = {}

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._load_from_disk()
        self.scheduler.start()
        for cfg in self.integrations.values():
            self._schedule(cfg)
        # Pick up YAML files edited or dropped in by hand, without a restart.
        self.scheduler.add_job(self._watch_disk, "interval", seconds=5, id="__watch__", replace_existing=True)

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def _snapshot_mtimes(self) -> dict[str, float]:
        return {str(p): p.stat().st_mtime for d in (INTEGRATIONS_DIR, ACTIONS_DIR) for p in d.glob("*.yaml")}

    def _load_from_disk(self) -> None:
        self.integrations, self.load_errors = load_integration_files()
        self.actions.reload()
        self._mtimes = self._snapshot_mtimes()

    async def _watch_disk(self) -> None:
        if self._snapshot_mtimes() == self._mtimes:
            return
        log.info("config change on disk detected, reloading")
        old = set(self.integrations)
        self._load_from_disk()
        for name in old - set(self.integrations):
            self._unschedule(name)
        for cfg in self.integrations.values():
            self._schedule(cfg)

    # ------------------------------------------------------------ scheduling
    def _schedule(self, cfg: IntegrationConfig) -> None:
        if not cfg.enabled:
            self._unschedule(cfg.name)
            return
        existing = self.scheduler.get_job(cfg.name)
        if existing and existing.kwargs.get("interval") == cfg.schedule_seconds:
            return  # unchanged schedule: keep the current timer
        self.scheduler.add_job(
            self.run_now, "interval", seconds=cfg.schedule_seconds, id=cfg.name, args=[cfg.name],
            kwargs={"interval": cfg.schedule_seconds}, replace_existing=True, max_instances=1, coalesce=True,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=1),
        )

    def _unschedule(self, name: str) -> None:
        if self.scheduler.get_job(name):
            self.scheduler.remove_job(name)

    def next_run(self, name: str) -> str | None:
        job = self.scheduler.get_job(name)
        return job.next_run_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if job and job.next_run_time else None

    # ------------------------------------------------------------ operations
    async def run_now(self, name: str, interval: int | None = None, wait: bool = False, prepare=None,
                      cfg_override: IntegrationConfig | None = None) -> dict[str, Any]:
        """Run one integration. `wait` queues behind a running run; `prepare` runs inside the lock first (demo controls)."""
        if name not in self.integrations:
            return {"status": "error", "error": f"Unknown integration '{name}'"}
        lock = self._locks.setdefault(name, asyncio.Lock())
        if lock.locked() and not wait:
            return {"status": "skipped", "error": "A run is already in progress"}
        async with lock:
            cfg = cfg_override or self.integrations.get(name)
            if cfg is None or not cfg.enabled and interval is not None:
                return {"status": "skipped", "error": "Integration is disabled"}
            missing = missing_settings(cfg)
            if missing:  # "Not configured" is a setup state, not a failure: no run is recorded
                return {"status": "not_configured", "missing": missing,
                        "error": f"Not configured: set {', '.join(missing)} in .env (or store them in the vault)"}
            if prepare:
                await prepare()
            result = await run_integration(cfg, self.db, self.actions.handle, transport=self.transport, sleep=self.sleep)
            if result.get("suspicious"):
                self.pause_suspicious(name, result["suspicious"])
            if self.alerter:
                try:
                    result["alert"] = await self.alerter.record(cfg, result)
                except Exception:  # alerting must never break ingestion
                    log.exception("failure alerting crashed for %s", name)
            return result

    # ------------------------------------------------------------ token safety
    def pause_suspicious(self, name: str, detail: dict[str, Any]) -> None:
        """Exfiltration guard fired: stop pulling data with this token until a human reviews it."""
        self.set_enabled(name, False)
        self.db.set_state(name, "suspicious", detail)
        log.warning("connector %s auto-paused as SUSPICIOUS", name)

    def resume(self, name: str) -> IntegrationConfig:
        self.db.clear_state(name)
        return self.set_enabled(name, True)

    def revoke(self, name: str) -> list[str]:
        """Disable the connector and wipe its stored secrets (tombstoned, so .env cannot bring them back)."""
        cfg = self.set_enabled(name, False)
        refs = secret_refs(cfg)
        if self.vault:
            for ref in refs:
                self.vault.revoke(ref)
        clear_oauth_cache()
        self.db.set_state(name, "revoked", {"secrets": refs})
        log.warning("connector %s revoked; secrets wiped: %s", name, ", ".join(refs))
        return refs

    def upsert(self, cfg: IntegrationConfig) -> None:
        """Save + go live immediately (no restart)."""
        save_integration_file(cfg)
        self.integrations[cfg.name] = cfg
        self.load_errors.pop(f"{cfg.name}.yaml", None)
        self._unschedule(cfg.name)  # force an immediate first run with the new config
        self._schedule(cfg)
        self._mtimes = self._snapshot_mtimes()

    def set_enabled(self, name: str, enabled: bool) -> IntegrationConfig:
        cfg = self.integrations[name].model_copy(update={"enabled": enabled})
        path = INTEGRATIONS_DIR / f"{name}.yaml"
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if re.search(r"(?m)^enabled:\s*\S+", text):
            # Flip just that line so hand-written comments in the YAML survive pause/resume.
            path.write_text(re.sub(r"(?m)^enabled:\s*\S+", f"enabled: {str(enabled).lower()}", text, count=1), encoding="utf-8")
            self.integrations[name] = cfg
            self._unschedule(name)
            self._schedule(cfg)
            self._mtimes = self._snapshot_mtimes()
        else:
            self.upsert(cfg)
        return cfg

    def remove(self, name: str) -> None:
        self._unschedule(name)
        self.integrations.pop(name, None)
        path = INTEGRATIONS_DIR / f"{name}.yaml"
        if path.exists():
            path.unlink()
        self._mtimes = self._snapshot_mtimes()

    def reset_demo(self) -> list[str]:
        """Remove non-seeded integrations, re-enable seeded ones, clear all data. Returns removed names."""
        removed = [n for n in list(self.integrations) if n not in SEEDED_INTEGRATIONS]
        for name in removed:
            self.remove(name)
        self.db.reset()
        for name in SEEDED_INTEGRATIONS:
            if name in self.integrations:
                if not self.integrations[name].enabled:
                    self.set_enabled(name, True)
                else:
                    self._unschedule(name)
                    self._schedule(self.integrations[name])
        return removed
