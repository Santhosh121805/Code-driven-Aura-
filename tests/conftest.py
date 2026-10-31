"""Shared fixtures. Mocks run in-process via httpx.ASGITransport: no ports, no network, deterministic."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Mock demo credentials (same public values as .env.example) - set before any module reads them.
# Real-source settings are explicitly blanked so tests never touch real APIs or real secrets.
os.environ.update({
    "MOCK_CLOUDTRAIL_TOKEN": "ct-demo-token-5e2b7d",
    "MOCK_FIREWALL_API_KEY": "fw-demo-key-2b8e41",
    "MOCK_OKTA_CLIENT_ID": "0oa-demo-client",
    "MOCK_OKTA_CLIENT_SECRET": "okta-demo-secret-8c41",
    "MOCK_JIRA_USER": "soc-bot@mitigata.local",
    "MOCK_JIRA_TOKEN": "jira-demo-token-91d2",
    "WRONG_SECRET": "definitely-wrong",
    "DEMO_MODE": "on",            # no random 429s / malformed records: tests are deterministic
    "FIREWALL_RATE_LIMIT": "off",
    "MALFORMED_RECORDS": "",
    "ANTHROPIC_API_KEY": "",
    "LLM_BASE_URL": "",
    "SLACK_WEBHOOK_URL": "",
    "SMTP_HOST": "",
    "INTEGRATION_HUB_ENV_FILE": "",  # never load the developer's .env (real secrets) into tests
})
for real in ("github_token", "GITHUB_OWNER", "GITHUB_REPO", "GITHUB_ORG", "okta_token", "OKTA_DOMAIN",
             "jira_email", "jira_token", "JIRA_DOMAIN", "nvd_api_key"):
    os.environ.pop(real, None)

from integration_platform import auth  # noqa: E402

# Dashboard sign-ins for the API tests: one user per role, all with this password (hashed like the real .env).
TEST_PASSWORD = "correct-horse-battery"
os.environ["PLUGSEC_USERS"] = ",".join(f"{role}:{role}:{auth.hash_password(TEST_PASSWORD)}" for role in auth.ROLES)

from integration_platform.config import parse_yaml, validate_integration  # noqa: E402
from integration_platform.db import Database  # noqa: E402
from integration_platform.engine import clear_oauth_cache  # noqa: E402
from tests.fakes import mock_cloudtrail, mock_firewall, mock_jira, mock_okta  # noqa: E402


def signed_in(client, role: str = "admin"):
    """Sign a TestClient in as the test user for `role` (the session cookie stays on the client)."""
    resp = client.post("/api/auth/login", json={"username": role, "password": TEST_PASSWORD})
    assert resp.status_code == 200, resp.text
    return client


async def no_sleep(_: float) -> None:
    """Backoff sleep replacement so retry tests run instantly."""


class SleepRecorder:
    """Records requested sleeps instead of sleeping."""

    def __init__(self):
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(round(seconds, 1))


@pytest.fixture(autouse=True)
def _fresh_state():
    clear_oauth_cache()
    for mock in (mock_cloudtrail, mock_firewall, mock_okta):
        mock.controls.reset()
    yield


@pytest.fixture
def db(tmp_path) -> Database:
    return Database(tmp_path / "test.db")


@pytest.fixture
def cloudtrail() -> httpx.ASGITransport:
    return httpx.ASGITransport(app=mock_cloudtrail.app)


@pytest.fixture
def firewall() -> httpx.ASGITransport:
    return httpx.ASGITransport(app=mock_firewall.app)


@pytest.fixture
def okta() -> httpx.ASGITransport:
    return httpx.ASGITransport(app=mock_okta.app)


@pytest.fixture
def jira(jira_env) -> httpx.ASGITransport:
    mock_jira._tickets.clear()
    mock_jira._counter = 0
    return httpx.ASGITransport(app=mock_jira.app)


@pytest.fixture
def jira_env(monkeypatch):
    """The ticket action targets the real Jira settings: point them at the fake Jira's credentials."""
    monkeypatch.setenv("JIRA_DOMAIN", "jira.test")
    monkeypatch.setenv("jira_email", os.environ["MOCK_JIRA_USER"])
    monkeypatch.setenv("jira_token", os.environ["MOCK_JIRA_TOKEN"])


FAKE_CONFIGS = ROOT / "tests" / "fakes" / "configs"  # the fake tools' configs: test-only, never loaded by the platform


def raw_config(name: str) -> dict:
    path = FAKE_CONFIGS / f"{name}.yaml"
    if not path.exists():
        path = ROOT / "configs" / "integrations" / f"{name}.yaml"
    return parse_yaml(path.read_text())


def load(name: str, stream: dict | None = None, **overrides):
    """Load a seeded integration config, apply top-level overrides and (optionally) overrides to its FIRST stream."""
    data = raw_config(name)
    data.update(overrides)
    if stream:
        data["streams"][0] = {**data["streams"][0], **stream}
    return validate_integration(data)


def only(name: str, stream_name: str, **stream_overrides):
    """A seeded config reduced to one of its streams (handy for focused engine tests)."""
    data = raw_config(name)
    s = next(x for x in data["streams"] if x["name"] == stream_name)
    data["streams"] = [{**s, **stream_overrides}]
    return validate_integration(data)


# What the wizard produces for the OAuth2 mock (Mock Okta): one events stream with Link pagination.
OKTA_CONFIG = {
    "name": "okta_wizard", "display_name": "Mock Okta (wizard)", "base_url": "http://localhost:9003",
    "auth": {"type": "oauth2_client_credentials", "token_url": "/oauth2/v1/token",
             "client_id": "${MOCK_OKTA_CLIENT_ID}", "client_secret": "${MOCK_OKTA_CLIENT_SECRET}"},
    "scopes": ["okta.logs.read"],
    "streams": [{
        "name": "events", "entity": "event", "endpoint": "/api/v1/logs", "pagination": {"type": "link"},
        "mapping": {"id": "uuid", "type": "eventType", "severity": "severity", "timestamp": "published",
                    "description": "displayMessage", "src_ip": "client.ipAddress", "user": "actor.alternateId"},
        "transforms": {"severity_map": {"DEBUG": "info", "INFO": "info", "WARN": "medium", "ERROR": "critical"}},
    }],
}


def okta_config(stream: dict | None = None, **overrides):
    data = {**OKTA_CONFIG, **overrides}
    data["streams"] = [{**OKTA_CONFIG["streams"][0], **(stream or {})}]
    return validate_integration(data)
