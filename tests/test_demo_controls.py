"""Demo controls against the real connectors, end to end in-process (fake GitHub; nothing reaches the internet)."""
import httpx
import pytest
from cryptography.fernet import Fernet

from integration_platform import config, demo, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.vault import Vault
from tests.conftest import SleepRecorder, load, no_sleep

recorder = SleepRecorder()


class Router(httpx.AsyncBaseTransport):
    """Fake api.github.com (rejects the demo's invalid token); every other address refuses connections, like a dead host."""

    async def handle_async_request(self, request):
        if request.url.host != "api.github.com":
            raise httpx.ConnectError(f"[Errno 111] Connection refused: {request.url.host}:{request.url.port}", request=request)
        if request.headers.get("Authorization") == f"Bearer {demo.INVALID_DEMO_TOKEN}":
            return httpx.Response(401, json={"message": "Bad credentials"}, request=request)
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "octo", "name": "Octo Cat"}, request=request)
        return httpx.Response(200, json=[], request=request)


@pytest.fixture
def registry(db, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    for k, v in {"github_token": "test-token-not-real", "GITHUB_OWNER": "octo", "GITHUB_REPO": "demo"}.items():
        monkeypatch.setenv(k, v)
    router = Router()
    reg = scheduler.Registry(db, ActionRunner(db, transport=router, sleep=no_sleep), Vault(db, Fernet.generate_key().decode()))
    reg.transport = router
    reg.sleep = recorder
    reg.integrations = {"github": load("github", enabled=True)}  # independent of a live pause on disk
    yield reg
    config.set_secret_lookup(None)


async def test_network_off_retries_1_2_4_then_failed_on_the_connector(registry, db):
    recorder.delays.clear()
    r = await demo.network_off(registry)
    assert r["status"] == "error" and r["retries"] == 3 and recorder.delays == [1, 2, 4]
    assert "connection failed" in r["error"] and "FAILED after 3 retries (waited 1s, 2s, 4s)" in r["error"]
    run = db.recent_runs("github")[0]
    assert run["status"] == "error" and registry.integrations["github"].base_url == "https://api.github.com"  # config untouched


async def test_repeated_failure_fails_threshold_times_then_recovers(registry, db):
    r = await demo.repeated_failure(registry)  # the alert itself is covered in test_alerts.py
    assert (r["failed_runs"], r["threshold"], r["recovery_run"]) == (3, 3, "success")
    assert [run["status"] for run in db.recent_runs("github")][:4] == ["success", "error", "error", "error"]


async def test_wrong_key_is_auth_failed_without_retries(registry):
    r = await demo.wrong_key(registry)
    assert r["status"] == "auth_failed" and r["http_status"] == 401 and r["retries"] == 0
    assert r["error"].startswith("Authentication failed: HTTP 401")


async def test_paused_connector_is_not_silently_rerun(registry):
    registry.integrations["github"] = registry.integrations["github"].model_copy(update={"enabled": False})
    with pytest.raises(demo.DemoError, match="paused"):
        await demo.network_off(registry)
