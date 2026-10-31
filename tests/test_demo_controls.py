"""Deterministic demo controls: mock /__demo endpoints and the platform-side triggers, end to end in-process."""
import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from integration_platform import config, demo, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.vault import Vault
from mocks import mock_cloudtrail, mock_firewall, mock_jira, mock_okta
from mocks.common import faults_on
from tests.conftest import SleepRecorder, load, no_sleep, okta_config

recorder = SleepRecorder()


class Router(httpx.AsyncBaseTransport):
    """Route requests to the in-process mock apps by port, like the real localhost services."""

    def __init__(self):
        self.apps = {9001: mock_cloudtrail.app, 9002: mock_firewall.app, 9003: mock_okta.app, 9004: mock_jira.app}

    async def handle_async_request(self, request):
        if request.url.port not in self.apps:  # nothing listening there, like a real network
            raise httpx.ConnectError(f"[Errno 111] Connection refused: {request.url.host}:{request.url.port}", request=request)
        return await httpx.ASGITransport(app=self.apps[request.url.port]).handle_async_request(request)


@pytest.fixture(autouse=True)
def _disarm():
    yield


@pytest.fixture
def registry(db, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    mock_jira._tickets.clear()
    vault = Vault(db, Fernet.generate_key().decode())
    router = Router()
    reg = scheduler.Registry(db, ActionRunner(db, transport=router, sleep=no_sleep), vault)
    reg.transport = router
    reg.sleep = recorder
    reg.integrations = {"acme_firewall": load("acme_firewall", retry={"max_retries": 4, "base_seconds": 0}),
                        "aws_cloudtrail": load("aws_cloudtrail"), "mock_okta": load("mock_okta")}
    yield reg
    config.set_secret_lookup(None)


def test_demo_mode_turns_random_faults_off(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "on")
    monkeypatch.delenv("FIREWALL_RATE_LIMIT", raising=False)
    assert faults_on("FIREWALL_RATE_LIMIT") is False and faults_on("MALFORMED_RECORDS") is False
    monkeypatch.setenv("DEMO_MODE", "off")
    assert faults_on("FIREWALL_RATE_LIMIT") is True
    monkeypatch.setenv("FIREWALL_RATE_LIMIT", "off")  # explicit override wins
    assert faults_on("FIREWALL_RATE_LIMIT") is False


def test_mock_rate_limit_control_is_exactly_n():
    client = TestClient(mock_firewall.app)
    headers = {"X-API-Key": "fw-demo-key-2b8e41"}
    assert client.post("/__demo/rate-limit-next", params={"count": 2}).json()["rate_limit_next"] == 2
    codes = [client.get("/logs", headers=headers).status_code for _ in range(4)]
    assert codes == [429, 429, 200, 200]


def test_mock_malformed_control_injects_exactly_one():
    client = TestClient(mock_cloudtrail.app)
    headers = {"Authorization": "Bearer ct-demo-token-5e2b7d"}
    client.post("/__demo/malformed-next", params={"kind": "bad_time"})
    first = client.get("/events", headers=headers).json()["Records"]
    second = client.get("/events", headers=headers).json()["Records"]
    assert len(first) == 5 and sum(r["eventTime"] == "not-a-timestamp" for r in first) == 1
    assert len(second) == 4 and all(r["eventTime"] != "not-a-timestamp" for r in second)
    assert client.post("/__demo/malformed-next", params={"kind": "nope"}).status_code == 400


def test_mock_bulk_export_control_is_one_page_of_20x():
    client = TestClient(mock_cloudtrail.app)
    headers = {"Authorization": "Bearer ct-demo-token-5e2b7d"}
    client.post("/__demo/bulk-export-next")
    bulk = client.get("/events", headers=headers).json()["Records"]
    assert len(bulk) == 80 and {r["userIdentity"]["userName"] for r in bulk} == {"svc-sales-integration"}
    assert len(client.get("/events", headers=headers).json()["Records"]) == 4
    client.post("/__demo/bulk-export-next")
    assert client.post("/__demo/reset").json()["bulk_next"] == 0


async def test_trigger_429_recovers_after_exactly_two_retries(registry):
    r = await demo.trigger_429(registry)
    assert (r["status"], r["retries"], r["records_fetched"]) == ("success", 2, 12 + 15)  # logs + devices


async def test_trigger_malformed_quarantines_one_record_and_run_continues(registry, db):
    r = await demo.trigger_malformed(registry, "mock_okta")
    assert (r["status"], r["quarantined"]) == ("success", 1)  # first response of the run (users page 1) carries it
    assert db.list_quarantine("mock_okta")[0]["reason"].startswith("unparseable time")


async def test_bulk_export_warms_baseline_then_pauses_connector_and_tickets(registry, db):
    r = await demo.simulate_bulk_export(registry)
    assert r["baseline_warmup_runs"] == 3 and r["status"] == "suspicious"
    assert r["suspicious"]["records"] == 88 and r["suspicious"]["baseline"] == 12  # 80-record page + 2 normal pages
    assert registry.integrations["aws_cloudtrail"].enabled is False
    assert db.get_state("aws_cloudtrail")["state"] == "suspicious"
    assert any(t["summary"] == "[CRITICAL] Possible token abuse: abnormal data volume from AWS CloudTrail (mock)" for t in mock_jira._tickets)
    with pytest.raises(demo.DemoError, match="paused"):
        await demo.trigger_malformed(registry, "aws_cloudtrail")  # a paused connector is not silently re-run


async def test_retry_after_control_waits_exactly_5s(registry):
    recorder.delays.clear()
    r = await demo.trigger_retry_after(registry)
    assert r["status"] == "success" and r["retries"] == 1 and recorder.delays == [5]
    assert "HTTP 429: waited 5s due to Retry-After" in r["retry_log"]


async def test_network_off_retries_1_2_4_then_failed_on_the_connector(registry, db):
    recorder.delays.clear()
    r = await demo.network_off(registry)
    assert r["status"] == "error" and r["retries"] == 3 and recorder.delays == [1, 2, 4]
    assert "connection failed" in r["error"] and "FAILED after 3 retries (waited 1s, 2s, 4s)" in r["error"]
    run = db.recent_runs("acme_firewall")[0]
    assert run["status"] == "error" and registry.integrations["acme_firewall"].base_url == "http://localhost:9002"  # config untouched


async def test_wrong_key_is_auth_failed_without_retries(registry):
    r = await demo.wrong_key(registry)  # no github in this registry: falls back to the firewall mock
    assert r["status"] == "auth_failed" and r["http_status"] == 401 and r["retries"] == 0
    assert r["error"].startswith("Authentication failed: HTTP 401")
