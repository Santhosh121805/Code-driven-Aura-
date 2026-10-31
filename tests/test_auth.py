"""Each auth type works, bad credentials give a clear, NON-retried 'Authentication failed'."""
import httpx
import pytest
from fastapi.testclient import TestClient

from integration_platform.engine import AuthError, NotConfiguredError, fetch_records, run_integration
from tests.fakes import mock_cloudtrail, mock_firewall, mock_jira, mock_okta
from tests.conftest import load, no_sleep, okta_config, only


def first(cfg):
    return cfg.streams[0]


async def test_bearer_ok(cloudtrail):
    cfg = load("aws_cloudtrail")
    records, stats = await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)
    assert len(records) == 12 and stats.pages == 3


async def test_bearer_wrong_token_is_auth_failed_and_not_retried():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(401, json={"message": "Bad credentials"})
    cfg = load("aws_cloudtrail", auth={"type": "bearer", "token": "${WRONG_SECRET}"})
    with pytest.raises(AuthError, match=r"Authentication failed: HTTP 401.*not retried.*\$\{WRONG_SECRET\}"):
        await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert calls["n"] == 1


async def test_missing_secret_is_not_configured(cloudtrail):
    cfg = load("aws_cloudtrail", auth={"type": "bearer", "token": "${NOT_SET_ANYWHERE}"})
    with pytest.raises(NotConfiguredError, match="NOT_SET_ANYWHERE is not set"):
        await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)


async def test_api_key_ok_and_wrong(firewall):
    cfg = only("acme_firewall", "logs")
    records, _ = await fetch_records(cfg, first(cfg), transport=firewall, sleep=no_sleep)
    assert len(records) == 12
    bad = only("acme_firewall", "logs").model_copy(update={"auth": load("acme_firewall").auth.model_copy(update={"api_key": "${WRONG_SECRET}"})})
    with pytest.raises(AuthError, match="HTTP 401"):
        await fetch_records(bad, first(bad), transport=firewall, sleep=no_sleep)


async def test_api_key_with_prefix_like_okta_ssws():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json=[])
    cfg = load("okta", base_url="https://example.okta.com",
               auth={"type": "api_key", "header": "Authorization", "prefix": "SSWS ", "api_key": "${WRONG_SECRET}"})
    await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert seen["auth"] == "SSWS definitely-wrong"


async def test_optional_api_key_is_omitted_when_unset():
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})
    cfg = load("nvd")  # nvd_api_key is not set in tests
    await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert "apikey" not in {k.lower() for k in seen["headers"]}


async def test_basic_ok_and_wrong(jira):
    from integration_platform.actions import ActionRunner
    from integration_platform.db import Database
    runner = ActionRunner(Database(":memory:"), transport=jira, sleep=no_sleep)
    event = {"source": "aws_cloudtrail", "id": "1", "severity": "critical", "description": "x", "host": "h", "timestamp": "t"}
    assert (await runner.fire(runner.actions["create_jira_ticket"], event))["status"] == "success"
    client = TestClient(mock_jira.app)
    assert client.post("/rest/api/3/issue", auth=("soc-bot@mitigata.local", "wrong"), json={}).status_code == 401


async def test_oauth2_client_credentials(okta):
    cfg = okta_config()
    records, stats = await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    assert len(records) == 24 and stats.pages == 3


async def test_oauth2_wrong_secret(okta):
    cfg = okta_config(auth={**okta_config().auth.model_dump(), "client_secret": "${WRONG_SECRET}"})
    with pytest.raises(AuthError, match="HTTP 401"):
        await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)


async def test_oauth2_token_without_required_scope_is_403(okta):
    cfg = okta_config(scopes=["okta.users.read"])
    with pytest.raises(AuthError, match="HTTP 403"):
        await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)


async def test_oauth2_refreshes_token_after_server_side_invalidation(okta):
    cfg = okta_config()
    await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    mock_okta.issuer._tokens.clear()
    records, _ = await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    assert len(records) == 24


async def test_auth_none_public_feed(cloudtrail):
    cfg = load("aws_cloudtrail", auth={"type": "none"},
               stream={"endpoint": "/kev", "pagination": {"type": "none"}, "records_path": "vulnerabilities", "params": {},
                       "mapping": {"id": "cveID", "description": "vulnerabilityName", "timestamp": "dateAdded"}})
    records, stats = await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)
    assert stats.pages == 1 and records[0]["cveID"].startswith("CVE-") and len(records) > 1000  # saved full KEV copy


async def test_auth_failure_stops_the_run_with_clear_error(db):
    cfg = load("mock_okta", auth={**load("mock_okta").auth.model_dump(), "client_secret": "${WRONG_SECRET}"})
    result = await run_integration(cfg, db, transport=httpx.ASGITransport(app=mock_okta.app), sleep=no_sleep)
    assert result["status"] == "error" and result["retries"] == 0
    assert result["error"].startswith("users: Authentication failed: HTTP 401")
    assert [s["status"] for s in result["streams"]] == ["error", "not run"]  # other streams would fail the same way


@pytest.mark.parametrize("app,method,path", [
    (mock_cloudtrail.app, "get", "/events"),
    (mock_firewall.app, "get", "/logs"),
    (mock_firewall.app, "get", "/devices"),
    (mock_okta.app, "get", "/api/v1/logs"),
    (mock_okta.app, "get", "/api/v1/users"),
    (mock_jira.app, "post", "/rest/api/3/issue"),
])
def test_every_mock_rejects_missing_credentials(app, method, path):
    client = TestClient(app)
    assert getattr(client, method)(path).status_code == 401
    assert getattr(client, method)(path, headers={"Authorization": "Bearer wrong", "X-API-Key": "wrong"}).status_code == 401


def test_okta_token_endpoint_rejects_unknown_scope():
    client = TestClient(mock_okta.app)
    r = client.post("/oauth2/v1/token", data={"grant_type": "client_credentials", "client_id": "0oa-demo-client",
                                             "client_secret": "okta-demo-secret-8c41", "scope": "okta.everything"})
    assert r.status_code == 400 and "invalid_scope" in r.text
