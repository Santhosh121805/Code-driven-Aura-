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
    assert counts == {"users": 10, "devices": 0, "events": 24, "repositories": 0}
    user = db.list_records("user", "mock_okta")[0][0]
    assert user["source"] == "mock_okta" and user["fetched_at"].endswith("Z") and "@mitigata-demo.in" in user["email"]


async def test_device_table_gets_every_field(db, firewall):
    await run_integration(load("acme_firewall"), db, transport=firewall, sleep=no_sleep)
    devices, total = db.list_records("device")
    assert total == 15
    for d in devices:
        assert all(d[f] for f in ("id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at")), d


def github_router(dependabot_status: int):
    """Fake GitHub: /user, /user/repos (2 repos), languages, readme, collaborators, dependabot (status configurable), repo events."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "octo", "name": "Octo Cat", "email": None})
        if path == "/user/repos":
            return httpx.Response(200, json=[
                {"id": 10, "full_name": "octo/demo", "html_url": "https://github.com/octo/demo", "description": "Demo app",
                 "topics": ["demo"], "language": "Python", "visibility": "private", "fork": False, "archived": False,
                 "default_branch": "main", "stargazers_count": 3, "forks_count": 1, "open_issues_count": 2,
                 "created_at": "2025-01-01T00:00:00Z", "pushed_at": "2026-10-30T08:00:00Z"},
                {"id": 11, "full_name": "octo/tools", "html_url": "https://github.com/octo/tools", "description": None,
                 "topics": [], "language": "Go", "visibility": "public", "fork": True, "archived": False,
                 "pushed_at": "2026-09-01T08:00:00Z"}])
        if path.endswith("/languages"):
            return httpx.Response(200, json={"Python": 300, "HTML": 100})
        if path.endswith("/readme"):
            import base64
            return httpx.Response(200, json={"content": base64.b64encode(b"# tools\n\nSmall CLI helpers for daily ops.").decode()})
        if path.endswith("/collaborators"):
            return httpx.Response(200, json=[{"id": 2, "login": "hubot", "role_name": "admin"}])
        if path.endswith("/dependabot/alerts"):
            if dependabot_status != 200:
                message = {403: "Dependabot alerts are disabled for this repository.", 404: "Not Found",
                           401: "Resource not accessible by personal access token"}[dependabot_status]
                return httpx.Response(403 if dependabot_status == 401 else dependabot_status, json={"message": message})
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


async def test_github_all_repositories_through_config_only(db, github_env):
    result = await run_integration(load("github"), db, transport=github_router(200), sleep=no_sleep)
    status = {s["name"]: s["status"] for s in result["streams"]}
    assert status == {"repositories": "ok", "repo_languages": "ok", "repo_readme": "ok", "dependabot_alerts": "ok",
                      "me": "ok", "collaborators": "ok", "org_members": "skipped: GITHUB_ORG not set"}
    repos = {r["full_name"]: r for r in db.list_records("repository", "github")[0]}
    demo, tools = repos["octo/demo"], repos["octo/tools"]
    assert (demo["url"], demo["primary_language"], demo["visibility"], demo["stars"], demo["topics"]) == (
        "https://github.com/octo/demo", "Python", "private", "3", ["demo"])
    assert demo["languages"]["Python"]["percent"] == 75.0 and demo["dependabot_status"] == "enabled"
    assert demo["summary"] is None and (tools["summary"], tools["summary_source"]) == ("Small CLI helpers for daily ops.", "README")
    events = db.list_records("event", "github")[0]
    assert {(e["id"], e["type"], e["severity"], e["description"], e["resource"]) for e in events} == {
        ("octo/demo#7", "dependabot_alert", "high", "lodash: Prototype pollution", "octo/demo"),
        ("octo/tools#7", "dependabot_alert", "high", "lodash: Prototype pollution", "octo/tools")}
    assert db.source_counts("github")["users"] == 2


@pytest.mark.parametrize("status,value", [(403, "disabled"), (404, "no access"), (401, "no access")])  # 401 here = 403 "not accessible"
async def test_github_dependabot_unavailable_is_skipped_per_repository(db, github_env, status, value):
    result = await run_integration(load("github"), db, transport=github_router(status), sleep=no_sleep)
    alerts = next(s for s in result["streams"] if s["name"] == "dependabot_alerts")
    assert result["status"] == "success" and alerts["status"] == "ok" and alerts["skipped"] == 2
    assert {r["dependabot_status"] for r in db.list_records("repository", "github")[0]} == {value}


@pytest.mark.parametrize("status", [403, 404])
async def test_fallback_stream_used_when_primary_unavailable(db, github_env, status):
    from integration_platform.config import validate_integration
    cfg = validate_integration({
        "name": "gh_single", "display_name": "GH", "base_url": "https://api.github.com", "auth": {"type": "bearer", "token": "${github_token}"},
        "streams": [
            {"name": "dependabot_alerts", "endpoint": "/repos/${GITHUB_OWNER}/${GITHUB_REPO}/dependabot/alerts",
             "mapping": {"id": "to_string(number)", "timestamp": "updated_at"}},
            {"name": "repo_events", "fallback_for": "dependabot_alerts", "endpoint": "/repos/${GITHUB_OWNER}/${GITHUB_REPO}/events",
             "mapping": {"id": "id", "type": "type", "timestamp": "created_at"}}]})
    result = await run_integration(cfg, db, transport=github_router(status), sleep=no_sleep)
    st = {s["name"]: s["status"] for s in result["streams"]}
    assert st["dependabot_alerts"].startswith(f"not available (HTTP {status})") and st["repo_events"] == "ok"
    assert result["status"] == "success"
    assert db.list_records("event", "gh_single")[0][0]["type"] == "PushEvent"


def test_missing_settings_drive_not_configured(monkeypatch):
    assert missing_settings(load("github")) == ["github_token"]  # the demo-repo streams are optional (requires_env)
    assert missing_settings(load("nvd")) == []  # optional key
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
