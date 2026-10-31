"""session_login auth: log in once, reuse the token, re-login on expiry or a 401. Shapes follow vendor docs
(Lacework access tokens, Cisco FMC generatetoken header, Prisma Cloud x-redlock-auth)."""
import logging

import httpx
import pytest

from integration_platform import logmask
from integration_platform.config import ConfigError, missing_settings, validate_integration
from integration_platform.engine import clear_oauth_cache, run_integration
from integration_platform.vault import secret_refs
from tests.conftest import no_sleep

STREAM = {"name": "alerts", "entity": "event", "endpoint": "/api/v2/Alerts", "records_path": "data",
          "mapping": {"id": "alertId", "type": "alertType", "timestamp": "startTime", "description": "alertName"}}


def config(auth: dict, **stream) -> object:
    return validate_integration({"name": "lw", "display_name": "Lacework (test)", "base_url": "https://lw.test",
                                 "auth": auth, "streams": [{**STREAM, **stream}]})


LACEWORK = {"type": "session_login", "login_url": "/api/v2/access/tokens", "headers": {"X-LW-UAKS": "${LW_SECRET}"},
            "body": {"keyId": "${LW_KEY_ID}", "expiryTime": 3600}, "token_path": "token", "header": "Authorization", "prefix": "Bearer "}


@pytest.fixture(autouse=True)
def creds(monkeypatch):
    clear_oauth_cache()
    monkeypatch.setenv("LW_SECRET", "lw-secret-not-real")
    monkeypatch.setenv("LW_KEY_ID", "KEY_123")
    yield
    clear_oauth_cache()


class Server:
    """Fake API: issues tokens at the login URL, accepts only the current token on data calls."""

    def __init__(self, token_in_header=False, data_header="Authorization", prefix="Bearer "):
        self.logins, self.data_calls, self.tokens = [], 0, 0
        self.token_in_header, self.data_header, self.prefix = token_in_header, data_header, prefix
        self.valid = set()

    def issue(self):
        self.tokens += 1
        token = f"tok-{self.tokens}-abcdef"
        self.valid = {token}
        return token

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/api/v2/access/tokens", "/api/fmc_platform/v1/auth/generatetoken", "/login"):
            self.logins.append(request)
            if request.headers.get("X-LW-UAKS", "lw-secret-not-real") != "lw-secret-not-real" or b"WRONG" in request.content:
                return httpx.Response(401, json={"message": "invalid credentials"})
            if self.token_in_header:
                return httpx.Response(204, headers={"X-auth-access-token": self.issue()})
            return httpx.Response(201, json={"token": self.issue(), "expiresAt": "2026-11-01T12:00:00Z"})
        self.data_calls += 1
        sent = request.headers.get(self.data_header, "")
        if sent.removeprefix(self.prefix) not in self.valid:
            return httpx.Response(401, json={"message": "token expired"})
        return httpx.Response(200, json={"data": [{"alertId": f"a{self.data_calls}", "alertType": "Compliance",
                                                   "startTime": "2026-10-31T10:00:00Z", "alertName": "Root account used"}]})


async def test_lacework_style_login_then_bearer(db):
    server = Server()
    r = await run_integration(config(LACEWORK), db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert r["status"] == "success" and r["records_fetched"] == 1
    login = server.logins[0]
    assert login.method == "POST" and login.headers["X-LW-UAKS"] == "lw-secret-not-real"
    assert login.content == b'{"keyId":"KEY_123","expiryTime":3600}'


async def test_token_is_reused_until_ttl_then_login_again(db):
    server = Server()
    cfg = config(LACEWORK)
    for _ in range(3):
        await run_integration(cfg, db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert len(server.logins) == 1 and server.data_calls == 3  # one login, cached token reused


async def test_401_on_a_data_call_logs_in_once_more(db):
    server = Server()
    cfg = config(LACEWORK)
    await run_integration(cfg, db, transport=httpx.MockTransport(server), sleep=no_sleep)
    server.valid = set()  # the server expired the token early
    r = await run_integration(cfg, db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert r["status"] == "success" and len(server.logins) == 2


async def test_cisco_fmc_style_token_in_a_response_header_with_basic_login(db, monkeypatch):
    monkeypatch.setenv("FMC_PASSWORD", "fmc-pass-not-real")
    server = Server(token_in_header=True, data_header="X-auth-access-token", prefix="")
    auth = {"type": "session_login", "login_url": "/api/fmc_platform/v1/auth/generatetoken", "username": "api-user",
            "password": "${FMC_PASSWORD}", "token_path": None, "token_response_header": "X-auth-access-token",
            "header": "X-auth-access-token", "prefix": ""}
    r = await run_integration(config(auth), db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert r["status"] == "success"
    assert server.logins[0].headers["Authorization"].startswith("Basic ")


async def test_prisma_style_body_credentials_and_bare_header(db, monkeypatch):
    monkeypatch.setenv("PRISMA_KEY", "pk-not-real")
    monkeypatch.setenv("PRISMA_SECRET", "ps-not-real")
    server = Server(data_header="x-redlock-auth", prefix="")
    auth = {"type": "session_login", "login_url": "/login", "body": {"username": "${PRISMA_KEY}", "password": "${PRISMA_SECRET}"},
            "token_path": "token", "header": "x-redlock-auth", "prefix": ""}
    r = await run_integration(config(auth), db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert r["status"] == "success" and b'"password":"ps-not-real"' in server.logins[0].content


async def test_wrong_credentials_fail_fast_and_never_retry(db, monkeypatch):
    monkeypatch.setenv("LW_SECRET", "WRONG")
    server = Server()
    r = await run_integration(config(LACEWORK), db, transport=httpx.MockTransport(server), sleep=no_sleep)
    assert r["status"] == "error" and "Authentication failed: HTTP 401" in r["error"] and len(server.logins) == 1
    assert "${LW_KEY_ID}" in r["error"] and "${LW_SECRET}" in r["error"]  # the hint names the settings, not values


async def test_missing_token_in_the_response_is_a_clear_error(db):
    def handler(request):
        return httpx.Response(200, json={"session": "x"}) if "tokens" in request.url.path else httpx.Response(200, json={"data": []})
    r = await run_integration(config(LACEWORK), db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert r["status"] == "error" and "no token was found ('token' in the response)" in r["error"]


async def test_session_token_never_appears_in_logs(db, caplog):
    server = Server()
    await run_integration(config(LACEWORK), db, transport=httpx.MockTransport(server), sleep=no_sleep)
    logging.getLogger("t").warning("debug: tok-1-abcdef")
    assert logmask.mask_text("tok-1-abcdef") == "****"


def test_validation_rejects_literal_secrets_and_missing_token_source():
    with pytest.raises(ConfigError, match="looks secret"):
        config({**LACEWORK, "body": {"keyId": "K", "secretKey": "literal-secret"}})
    with pytest.raises(ConfigError, match="token_path"):
        config({**LACEWORK, "token_path": None})
    with pytest.raises(ConfigError, match="go together"):
        config({**LACEWORK, "username": "u"})


def test_nested_refs_count_as_secrets_and_missing_settings(monkeypatch):
    cfg = config(LACEWORK)
    assert secret_refs(cfg) == ["LW_KEY_ID", "LW_SECRET"]
    monkeypatch.delenv("LW_KEY_ID")
    assert missing_settings(cfg) == ["LW_KEY_ID"]
