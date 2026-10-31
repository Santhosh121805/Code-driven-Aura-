"""Streams + the common schema (FR-11): one config, several endpoints, each mapped to users / devices / events."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet

from integration_platform import config, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.config import missing_settings
from integration_platform.engine import render_params, run_integration, template_context
from integration_platform.vault import Vault
from tests.conftest import load, no_sleep


async def test_one_connector_fills_two_entity_tables(db, okta):
    result = await run_integration(load("mock_okta"), db, transport=okta, sleep=no_sleep)
    users, events = result["streams"]
    assert (users["entity"], users["status"], users["fetched"]) == ("user", "ok", 10)
    assert (events["entity"], events["status"], events["fetched"]) == ("event", "ok", 24)
    counts = db.source_counts("mock_okta")
    assert counts == {"users": 10, "devices": 0, "events": 24}
    user = db.list_records("user", "mock_okta")[0][0]
    assert user["source"] == "mock_okta" and user["fetched_at"].endswith("Z") and "@mitigata-demo.in" in user["email"]


async def test_device_table_gets_every_field(db, firewall):
    await run_integration(load("acme_firewall"), db, transport=firewall, sleep=no_sleep)
    devices, total = db.list_records("device")
    assert total == 15
    for d in devices:
        assert all(d[f] for f in ("id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at")), d


def github_router(dependabot_status: int):
    """Fake GitHub: /user, collaborators, dependabot (status configurable), repo events."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "octo", "name": "Octo Cat", "email": None})
        if path.endswith("/collaborators"):
            return httpx.Response(200, json=[{"id": 2, "login": "hubot", "role_name": "admin"}])
        if path.endswith("/dependabot/alerts"):
            if dependabot_status != 200:
                return httpx.Response(dependabot_status, json={"message": "Dependabot alerts are disabled for this repository."})
            return httpx.Response(200, json=[{"number": 7, "updated_at": "2026-10-30T10:00:00Z",
                                              "security_advisory": {"severity": "high", "summary": "Prototype pollution"},
                                              "dependency": {"package": {"name": "lodash"}}}])
        if path.endswith("/events"):
            return httpx.Response(200, json=[{"id": "123", "type": "PushEvent", "created_at": "2026-10-30T09:00:00Z",
                                              "actor": {"login": "octo"}, "repo": {"name": "octo/demo"}}])
        return httpx.Response(404, json={})
    return httpx.MockTransport(handler)


@pytest.fixture
def github_env(monkeypatch):
    for k, v in {"github_token": "test-token-not-real", "GITHUB_OWNER": "octo", "GITHUB_REPO": "demo"}.items():
        monkeypatch.setenv(k, v)


async def test_requires_env_skips_optional_stream_and_dependabot_wins(db, github_env):
    result = await run_integration(load("github"), db, transport=github_router(200), sleep=no_sleep)
    status = {s["name"]: s["status"] for s in result["streams"]}
    assert status == {"me": "ok", "collaborators": "ok", "org_members": "skipped: GITHUB_ORG not set",
                      "dependabot_alerts": "ok", "repo_events": "skipped: dependabot_alerts is available"}
    event = db.list_records("event", "github")[0][0]
    assert (event["id"], event["type"], event["severity"], event["description"]) == (
        "dependabot-7", "dependabot_alert", "high", "Prototype pollution (lodash)")
    assert db.source_counts("github")["users"] == 2


@pytest.mark.parametrize("status", [403, 404])
async def test_fallback_stream_used_when_dependabot_unavailable(db, github_env, status):
    result = await run_integration(load("github"), db, transport=github_router(status), sleep=no_sleep)
    st = {s["name"]: s["status"] for s in result["streams"]}
    assert st["dependabot_alerts"].startswith(f"not available (HTTP {status})") and st["repo_events"] == "ok"
    assert result["status"] == "success"
    assert db.list_records("event", "github")[0][0]["type"] == "PushEvent"


def test_missing_settings_drive_not_configured(monkeypatch):
    assert missing_settings(load("github")) == ["GITHUB_OWNER", "GITHUB_REPO", "github_token"]
    assert missing_settings(load("nvd")) == []  # optional key
    monkeypatch.setenv("GITHUB_OWNER", "o")
    monkeypatch.setenv("GITHUB_REPO", "r")
    monkeypatch.setenv("github_token", "t")
    assert missing_settings(load("github")) == []  # GITHUB_ORG only needed for its optional stream


async def test_registry_skips_not_configured_connector_without_recording_a_failure(db, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    reg = scheduler.Registry(db, ActionRunner(db, sleep=no_sleep), Vault(db, Fernet.generate_key().decode()))
    reg.integrations["okta"] = load("okta")
    result = await reg.run_now("okta")
    config.set_secret_lookup(None)
    assert result["status"] == "not_configured" and result["missing"] == ["OKTA_DOMAIN", "okta_token"]
    assert db.recent_runs("okta") == []


def test_nvd_date_window_params_render_from_last_sync():
    params = load("nvd").streams[0].params
    first = render_params(params, template_context(None))
    start = datetime.strptime(first["lastModStartDate"], "%Y-%m-%dT%H:%M:%S.000Z")
    end = datetime.strptime(first["lastModEndDate"], "%Y-%m-%dT%H:%M:%S.000Z")
    assert timedelta(hours=23) < end - start <= timedelta(days=1, minutes=1)  # first run: last 24h (<= 120-day window)
    later = render_params(params, template_context("2026-10-31T05:00:00Z"))
    assert later["lastModStartDate"] == "2026-10-31T05:00:00.000Z"


def test_env_refs_in_endpoint_are_resolved(monkeypatch):
    monkeypatch.setenv("GITHUB_OWNER", "octo")
    monkeypatch.setenv("GITHUB_REPO", "demo")
    from integration_platform.engine import _Request
    cfg = load("github")
    assert _Request(cfg, cfg.stream("collaborators")).url == "https://api.github.com/repos/octo/demo/collaborators"
