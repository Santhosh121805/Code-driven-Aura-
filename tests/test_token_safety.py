"""Token safety (INC-05, Salesloft Drift stolen-OAuth-token breach): encryption at rest, log masking, scopes,
secret age, exfiltration guard with auto-pause, and revoke."""
import io
import logging
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet

from integration_platform import config, logmask, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.config import MissingSecretError, resolve_env, risky_scopes
from integration_platform.engine import run_integration
from integration_platform.vault import Vault, connector_secret_status, ensure_secrets_key, parse_age_overrides, secret_refs
from tests.fakes import mock_jira
from tests.conftest import load, no_sleep, okta_config


@pytest.fixture
def vault(db):
    v = Vault(db, Fernet.generate_key().decode())
    v.activate()
    yield v
    config.set_secret_lookup(None)


# ------------------------------------------------------------------ encryption at rest
def test_secrets_are_encrypted_at_rest(db, vault):
    vault.set("MOCK_OKTA_CLIENT_SECRET", "okta-demo-secret-8c41")
    raw = db.get_secret("MOCK_OKTA_CLIENT_SECRET")["ciphertext"]
    assert raw.startswith("gAAAAA") and "okta-demo-secret" not in raw   # Fernet token, no plaintext
    assert vault.get("MOCK_OKTA_CLIENT_SECRET") == "okta-demo-secret-8c41"


def test_vault_is_used_before_environment(vault, monkeypatch):
    monkeypatch.setenv("SOME_TOKEN", "from-env")
    assert resolve_env("${SOME_TOKEN}") == "from-env"
    vault.set("SOME_TOKEN", "from-vault")
    assert resolve_env("Bearer ${SOME_TOKEN}") == "Bearer from-vault"


def test_wrong_master_key_falls_back_and_reimports(db, monkeypatch):
    Vault(db, Fernet.generate_key().decode()).set("MOCK_FIREWALL_API_KEY", "old")
    other = Vault(db, Fernet.generate_key().decode())   # e.g. SECRETS_KEY changed
    assert other.get("MOCK_FIREWALL_API_KEY") is None            # undecryptable copy ignored, no crash
    assert other.import_from_env(["MOCK_FIREWALL_API_KEY"]) == ["MOCK_FIREWALL_API_KEY"]
    assert other.get("MOCK_FIREWALL_API_KEY") == os.environ["MOCK_FIREWALL_API_KEY"]


def test_secrets_key_generated_into_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETS_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=1\nSECRETS_KEY=\n", encoding="utf-8")
    key = ensure_secrets_key(env_file)
    Fernet(key.encode())  # valid key
    assert f"SECRETS_KEY={key}" in env_file.read_text() and os.environ["SECRETS_KEY"] == key
    assert ensure_secrets_key(env_file) == key  # idempotent


# ------------------------------------------------------------------ log masking
def test_logs_mask_token_like_strings():
    logmask.remember("okta-demo-secret-8c41")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(logmask.MaskingFilter())
    logger = logging.getLogger("test.mask")
    logger.addHandler(handler)
    logger.propagate = False
    logger.warning("auth header Authorization: Bearer abcDEF123456789xyz")
    logger.warning("token form client_secret=okta-demo-secret-8c41&grant_type=client_credentials")
    logger.warning('response {"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlMTIz", "scope": "okta.logs.read"}')
    logger.warning("leaked key AKIAIOSFODNN7EXAMPLE and stored gAAAAABlongfernettokenvalue1234567890")
    logger.warning("raw value %s in an f-string", "okta-demo-secret-8c41")
    out = stream.getvalue()
    for secret in ("abcDEF123456789xyz", "okta-demo-secret-8c41", "eyJhbGci", "AKIAIOSFODNN7EXAMPLE", "gAAAAABlongfernet"):
        assert secret not in out, secret
    assert "Bearer ****" in out and "okta.logs.read" in out  # non-secret context is preserved


async def test_stored_run_errors_are_masked(db, monkeypatch):
    monkeypatch.setenv("LEAKY", "super-secret-value-123")
    cfg = load("acme_firewall", auth={"type": "api_key", "header": "X-API-Key", "api_key": "${LEAKY}"})

    def handler(request):
        return httpx.Response(400, text=f"bad key {request.headers['X-API-Key']}")
    result = await run_integration(cfg, db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert "super-secret-value-123" not in result["error"] and "****" in result["error"]


# ------------------------------------------------------------------ scopes
def test_risky_scope_detection():
    assert risky_scopes(["okta.logs.read", "cloudtrail:LookupEvents", "logs:read"]) == []
    assert risky_scopes(["okta.users.manage", "s3:*", "okta.logs.read", "api", "repo:write"]) == ["okta.users.manage", "s3:*", "api", "repo:write"]


async def test_oauth_scopes_are_requested_at_token_endpoint():
    seen = {}

    def handler(request):
        if request.url.path == "/oauth2/v1/token":
            seen["form"] = request.content.decode()
            return httpx.Response(200, json={"access_token": "t", "expires_in": 60})
        return httpx.Response(200, json=[])
    from integration_platform.engine import fetch_records
    cfg = okta_config(scopes=["okta.logs.read", "okta.users.read"])
    await fetch_records(cfg, cfg.streams[0], transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert "scope=okta.logs.read+okta.users.read" in seen["form"]


# ------------------------------------------------------------------ secret age
def test_secret_age_and_rotation_warning(vault):
    vault.set("MOCK_FIREWALL_API_KEY", "k", created_at=datetime.now(timezone.utc) - timedelta(days=95))
    status = connector_secret_status(load("acme_firewall"), vault)
    assert status == [{"name": "MOCK_FIREWALL_API_KEY", "in_vault": True, "created_at": status[0]["created_at"], "age_days": 95,
                       "revoked": False, "rotate": True, "max_age_days": 90}]
    assert connector_secret_status(load("acme_firewall", secret_max_age_days=120), vault)[0]["rotate"] is False


def test_demo_age_override_on_import(vault):
    assert parse_age_overrides("MOCK_FIREWALL_API_KEY:95, X:bad,Y:3") == {"MOCK_FIREWALL_API_KEY": 95, "Y": 3}
    vault.import_from_env(["MOCK_FIREWALL_API_KEY", "MOCK_CLOUDTRAIL_TOKEN"], {"MOCK_FIREWALL_API_KEY": 95})
    assert vault.info("MOCK_FIREWALL_API_KEY")["age_days"] == 95 and vault.info("MOCK_CLOUDTRAIL_TOKEN")["age_days"] == 0
    assert secret_refs(okta_config()) == ["MOCK_OKTA_CLIENT_ID", "MOCK_OKTA_CLIENT_SECRET"]
    from integration_platform.config import load_action_files
    assert secret_refs(load_action_files()[0]["create_jira_ticket"]) == ["JIRA_DOMAIN", "jira_email", "jira_token"]  # actions too


# ------------------------------------------------------------------ exfiltration guard
def records(n: int, start: int = 0) -> dict:
    return {"Records": [{"eventID": f"ct-{start + i}", "eventName": "GetObject", "eventSource": "s3.amazonaws.com", "eventTime": "2026-10-31T05:49:32Z",
                         "userIdentity": {"arn": "arn:aws:iam::491085362710:user/svc-sales-integration"},
                         "sourceIPAddress": "45.155.205.233"} for i in range(n)]}


def volume(n: int, start: int):
    return httpx.MockTransport(lambda request: httpx.Response(200, json=records(n, start)))


async def test_guard_flags_bulk_export_raises_critical_alert_and_ticket(db, jira):
    runner = ActionRunner(db, transport=jira, sleep=no_sleep)
    cfg = load("aws_cloudtrail").model_copy(update={"name": "okta", "display_name": "Okta"})  # a ticketed source
    for i in range(3):  # baseline: 12 records per run
        r = await run_integration(cfg, db, runner.handle, transport=volume(12, i * 100), sleep=no_sleep)
        assert r["suspicious"] is None
    r = await run_integration(cfg, db, runner.handle, transport=volume(240, 1000), sleep=no_sleep)  # ~20x
    s = r["suspicious"]
    assert r["status"] == "suspicious" and s["records"] == 240 and s["baseline"] == 12 and s["threshold"] == 60 and s["ratio"] == 20.0
    event = db.get_event("okta", s["event_id"])
    assert event["severity"] == "critical" and event["description"] == "Possible token abuse: abnormal data volume from Okta" and event["type"] == "token_abuse"
    ticket = next(t for t in mock_jira._tickets if "token abuse" in t["summary"])
    assert ticket["summary"] == "[CRITICAL] Possible token abuse: abnormal data volume from Okta"
    assert event["ticket_key"] == ticket["key"]
    assert db.baseline_counts("okta", 10) == [12, 12, 12]  # suspicious run excluded from the baseline


async def test_guard_needs_a_baseline_and_ignores_small_feeds(db):
    cfg = load("aws_cloudtrail")
    r = await run_integration(cfg, db, transport=volume(500, 0), sleep=no_sleep)
    assert r["suspicious"] is None  # first run: no baseline yet
    small = cfg.model_copy(update={"name": "tiny_feed"})
    for i in range(3):
        await run_integration(small, db, transport=volume(2, 10_000 + i * 10), sleep=no_sleep)
    r = await run_integration(small, db, transport=volume(40, 20_000), sleep=no_sleep)
    assert r["suspicious"] is None  # 20x a baseline of 2, but under min_records (50): noise, not exfiltration


# ------------------------------------------------------------------ auto-pause, resume, revoke
@pytest.fixture
def registry(db, vault, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    vault.import_from_env(["MOCK_CLOUDTRAIL_TOKEN"])
    reg = scheduler.Registry(db, ActionRunner(db, sleep=no_sleep), vault)
    reg.integrations["aws_cloudtrail"] = load("aws_cloudtrail")
    return reg


async def test_suspicious_connector_is_auto_paused_then_resumed(registry, db):
    for i in range(3):
        registry.transport = volume(12, i * 100)
        await registry.run_now("aws_cloudtrail")
    registry.transport = volume(240, 5000)
    result = await registry.run_now("aws_cloudtrail")
    assert result["status"] == "suspicious"
    assert registry.integrations["aws_cloudtrail"].enabled is False
    assert db.get_state("aws_cloudtrail")["state"] == "suspicious"
    registry.resume("aws_cloudtrail")
    assert registry.integrations["aws_cloudtrail"].enabled is True and db.get_state("aws_cloudtrail") is None


async def test_resume_accepts_the_new_volume_and_relearns_the_baseline(registry, db):
    """Real case: GitHub's first Dependabot scan jumped from 2 to 183 records per run. After a human resumes,
    runs at the new legitimate volume must not pause the connector again; a later >5x jump still does."""
    for i in range(3):
        registry.transport = volume(12, i * 100)
        await registry.run_now("aws_cloudtrail")
    registry.transport = volume(240, 5000)
    assert (await registry.run_now("aws_cloudtrail"))["status"] == "suspicious"
    registry.resume("aws_cloudtrail")
    for i in range(3):
        registry.transport = volume(240, 5000)  # same full listing every run, like Dependabot alerts
        assert (await registry.run_now("aws_cloudtrail"))["status"] == "success"
    assert db.baseline_counts("aws_cloudtrail", 10) == [240, 240, 240]
    registry.transport = volume(1300, 9000)  # > 5x the new baseline of 240
    assert (await registry.run_now("aws_cloudtrail"))["status"] == "suspicious"


def test_pause_and_resume_keep_hand_written_yaml_comments(registry, tmp_path):
    from tests.conftest import ROOT
    original = (ROOT / "tests/fakes/configs/aws_cloudtrail.yaml").read_text(encoding="utf-8")
    (tmp_path / "aws_cloudtrail.yaml").write_text(original, encoding="utf-8")
    registry.pause_suspicious("aws_cloudtrail", {"records": 88, "baseline": 12})
    paused = (tmp_path / "aws_cloudtrail.yaml").read_text(encoding="utf-8")
    assert "enabled: false" in paused and "# CloudTrail has no severity field" in paused
    registry.resume("aws_cloudtrail")
    assert (tmp_path / "aws_cloudtrail.yaml").read_text(encoding="utf-8") == original  # byte-for-byte restored


async def test_revoke_disables_and_wipes_secret_even_if_env_has_it(registry, db, vault):
    assert resolve_env("${MOCK_CLOUDTRAIL_TOKEN}") == os.environ["MOCK_CLOUDTRAIL_TOKEN"]
    wiped = registry.revoke("aws_cloudtrail")
    assert wiped == ["MOCK_CLOUDTRAIL_TOKEN"]
    assert registry.integrations["aws_cloudtrail"].enabled is False
    assert db.get_state("aws_cloudtrail")["state"] == "revoked"
    assert db.get_secret("MOCK_CLOUDTRAIL_TOKEN")["ciphertext"] is None
    with pytest.raises(MissingSecretError, match="revoked"):
        resolve_env("${MOCK_CLOUDTRAIL_TOKEN}")  # tombstone: .env cannot resurrect it
    registry.transport = volume(12, 0)
    r = await registry.run_now("aws_cloudtrail")
    assert r["status"] == "error" and "revoked" in r["error"]
    vault.set("MOCK_CLOUDTRAIL_TOKEN", "rotated-token-value")  # storing a new secret re-enables use
    assert resolve_env("${MOCK_CLOUDTRAIL_TOKEN}") == "rotated-token-value"


def test_reset_can_restore_demo_secret_age(vault):
    vault.set("MOCK_FIREWALL_API_KEY", "k")
    assert vault.info("MOCK_FIREWALL_API_KEY")["age_days"] == 0
    vault.set_age("MOCK_FIREWALL_API_KEY", 95)
    assert vault.info("MOCK_FIREWALL_API_KEY")["age_days"] == 95
    vault.set_age("NOT_STORED", 95)  # no-op for unknown names
    assert vault.info("NOT_STORED")["in_vault"] is False
