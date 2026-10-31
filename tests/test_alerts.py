"""B-4: alert on repeated failure - one alert per failure streak, a recovery message, banner/log fallback."""
import httpx
import pytest

from integration_platform.actions import ActionRunner
from integration_platform.alerts import FailureAlerter
from mocks import mock_jira
from tests.conftest import load, no_sleep

FAIL = {"status": "error", "error": "logs: connection failed (network down or host unreachable) - FAILED after 3 retries"}
OK = {"status": "success"}


@pytest.fixture
def slack(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "http://localhost:9004/slack/webhook")
    mock_jira._slack.clear()
    return httpx.ASGITransport(app=mock_jira.app)


async def test_one_alert_per_streak_then_recovered(db, slack):
    alerter = FailureAlerter(db, ActionRunner(db, transport=slack, sleep=no_sleep))
    cfg = load("acme_firewall")  # alert_after_failures defaults to 3
    assert await alerter.record(cfg, FAIL) is None
    assert await alerter.record(cfg, FAIL) is None
    alert = await alerter.record(cfg, FAIL)
    assert alert["kind"] == "failure_alert" and alert["channels"] == ["ui", "log", "slack_failure_alert"]
    assert "Acme Firewall (mock) failed 3 runs in a row" in alert["message"]
    assert await alerter.record(cfg, FAIL) is None  # 4th failure: same streak, no second alert
    assert len(mock_jira._slack) == 1 and "failed 3 runs in a row" in mock_jira._slack[0]["text"]
    recovered = await alerter.record(cfg, OK)
    assert recovered["kind"] == "recovered" and "recovered after 4 failed run(s)" in recovered["message"]
    assert len(mock_jira._slack) == 2 and "recovered" in mock_jira._slack[1]["text"]
    assert db.get_failure_state("acme_firewall")["streak"] == 0
    assert [n["kind"] for n in db.list_notifications()] == ["recovered", "failure_alert"]


async def test_new_streak_alerts_again_and_threshold_is_configurable(db, slack):
    alerter = FailureAlerter(db, ActionRunner(db, transport=slack, sleep=no_sleep))
    cfg = load("acme_firewall", alert_after_failures=2)
    for _ in range(2):
        await alerter.record(cfg, FAIL)
    await alerter.record(cfg, OK)
    await alerter.record(cfg, FAIL)
    second = await alerter.record(cfg, FAIL)
    assert second["kind"] == "failure_alert" and len([m for m in mock_jira._slack if "failed" in m["text"]]) == 2


async def test_without_webhook_banner_and_log_only(db, monkeypatch, caplog):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    alerter = FailureAlerter(db, ActionRunner(db, sleep=no_sleep))
    cfg = load("acme_firewall")
    for _ in range(3):
        alert = await alerter.record(cfg, FAIL)
    assert alert["channels"] == ["ui", "log"]
    assert db.list_notifications()[0]["kind"] == "failure_alert"
    assert any("ALERT failure_alert" in r.message for r in caplog.records)


async def test_not_configured_and_skipped_runs_do_not_count(db):
    alerter = FailureAlerter(db, ActionRunner(db, sleep=no_sleep))
    cfg = load("okta")
    for _ in range(5):
        await alerter.record(cfg, {"status": "not_configured"})
    assert db.get_failure_state("okta")["streak"] == 0


async def test_alert_text_is_masked(db, slack, monkeypatch):
    from integration_platform import logmask
    logmask.remember("leaky-secret-value-42")
    alerter = FailureAlerter(db, ActionRunner(db, transport=slack, sleep=no_sleep))
    cfg = load("acme_firewall", alert_after_failures=1)
    alert = await alerter.record(cfg, {"status": "error", "error": "HTTP 400: bad key leaky-secret-value-42"})
    assert "leaky-secret-value-42" not in alert["message"] and "leaky-secret-value-42" not in mock_jira._slack[-1]["text"]


async def test_repeated_failure_demo_through_registry(db, tmp_path, monkeypatch, slack):
    """The registry wires the alerter: N failed runs of a connector -> one alert; a good run -> recovered."""
    from integration_platform import config, demo, scheduler
    from tests.test_demo_controls import Router
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    router = Router()
    runner = ActionRunner(db, transport=router, sleep=no_sleep)
    reg = scheduler.Registry(db, runner, None, FailureAlerter(db, runner))
    reg.transport, reg.sleep = router, no_sleep
    reg.integrations["acme_firewall"] = load("acme_firewall")
    r = await demo.repeated_failure(reg)
    assert r["failed_runs"] == 3 and len(r["alerts"]) == 1 and r["alerts"][0]["kind"] == "failure_alert"
    assert r["recovery_run"] == "success" and r["recovery"]["kind"] == "recovered"
    assert [m["text"][:30] for m in mock_jira._slack][0].startswith(":rotating_light:")
