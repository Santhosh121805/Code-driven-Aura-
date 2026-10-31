"""API endpoints that need no running scheduler (lifespan not started: no background jobs, no file writes)."""
from fastapi.testclient import TestClient

from integration_platform.api import app
from tests.conftest import OKTA_CONFIG, signed_in

client = signed_in(TestClient(app))


def test_schema_endpoint_describes_streams():
    schema = client.get("/api/schema").json()
    assert schema["title"] == "IntegrationConfig" and {"auth", "streams", "rate_limit", "retry"} <= set(schema["properties"])
    assert schema["$defs"]["Stream"]["properties"]["entity"]["enum"] == ["user", "device", "event"]


def test_validate_returns_friendly_errors():
    r = client.post("/api/integrations/validate", json={"config": {**OKTA_CONFIG, "auth": {"type": "magic"}}})
    assert r.status_code == 422
    assert r.json()["errors"] == ["auth.type must be one of: none, bearer, api_key, basic, oauth2_client_credentials, session_login"]


def test_validate_accepts_yaml_and_never_contains_secret_values():
    yaml_text = client.post("/api/integrations/validate", json={"config": OKTA_CONFIG}).json()["yaml"]
    r = client.post("/api/integrations/validate", json={"yaml": yaml_text})
    assert r.status_code == 200
    assert "${MOCK_OKTA_CLIENT_SECRET}" in r.json()["yaml"] and "okta-demo-secret-8c41" not in r.json()["yaml"]


def test_validate_reports_missing_settings_for_not_configured_sources():
    real = {**OKTA_CONFIG, "name": "okta_real", "base_url": "https://${OKTA_DOMAIN}",
            "auth": {"type": "api_key", "header": "Authorization", "prefix": "SSWS ", "api_key": "${okta_token}"}}
    r = client.post("/api/integrations/validate", json={"config": real})
    assert r.status_code == 200 and r.json()["missing"] == ["OKTA_DOMAIN", "okta_token"]


def test_test_endpoint_says_not_configured_instead_of_failing():
    real = {**OKTA_CONFIG, "name": "okta_real", "base_url": "https://${OKTA_DOMAIN}"}
    r = client.post("/api/integrations/test", json={"config": real}).json()
    assert r["ok"] is False and r["errors"][0].startswith("Not configured: set OKTA_DOMAIN")


def test_suggest_mapping_endpoint_per_entity():
    r = client.post("/api/ai/suggest-mapping", json={"sample": '[{"uuid": "a", "severity": "WARN", "published": "2026-10-31T05:00:00Z"}]'})
    assert r.status_code == 200 and r.json()["engine"] == "Rule-based fallback" and r.json()["entity"] == "event"
    r = client.post("/api/ai/suggest-mapping", json={"entity": "user", "sample": '[{"id": "1", "email": "a@b.in", "status": "ACTIVE"}]'})
    assert r.json()["mapping"] == {"id": "id", "email": "email", "status": "status"}
    assert client.post("/api/ai/suggest-mapping", json={"sample": "{not json"}).status_code == 422
    assert client.post("/api/ai/suggest-mapping", json={"entity": "host", "sample": "[]"}).status_code == 422


def test_trim_sample_keeps_shape_but_limits_records():
    from integration_platform.api import _trim_sample
    big = {"catalogVersion": "x", "vulnerabilities": [{"cveID": f"CVE-2026-{i:04d}"} for i in range(1766)]}
    trimmed, count = _trim_sample(big)
    assert count == 1766 and len(trimmed["vulnerabilities"]) == 20 and trimmed["catalogVersion"] == "x"
    assert len(big["vulnerabilities"]) == 1766  # original untouched


def test_startup_bootstrap_encrypts_every_referenced_secret(tmp_path, monkeypatch):
    """The lifespan's secret bootstrap over the real seeded configs (integrations AND actions). Unset real secrets are skipped."""
    from cryptography.fernet import Fernet

    from integration_platform import api, config
    from integration_platform.db import Database
    from integration_platform.vault import Vault
    api.state.db = Database(tmp_path / "boot.db")
    api.state.vault = Vault(api.state.db, Fernet.generate_key().decode())
    monkeypatch.setenv("github_token", "test-gh-token-not-real")
    monkeypatch.setenv("jira_token", "test-jira-token-not-real")  # referenced by the integration AND the ticket action
    try:
        api.bootstrap_secrets()
        names = {r["name"] for r in api.state.db.list_secrets()}
        assert {"github_token", "jira_token"} <= names
        assert not names & {"okta_token", "nvd_api_key"}  # not set in tests
    finally:
        config.set_secret_lookup(None)


def test_test_endpoint_reports_unreachable_tool_without_500():
    cfg = {**OKTA_CONFIG, "base_url": "http://127.0.0.1:9", "retry": {"max_retries": 0}}
    r = client.post("/api/integrations/test", json={"config": cfg})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "connection failed" in r.json()["errors"][0]
