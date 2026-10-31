"""B-4 Slack delivery against a fake that answers like a real incoming webhook (plain text "ok", or Slack's error codes)."""
import json
import logging

import httpx
import pytest

from integration_platform.actions import ActionRunner
from integration_platform.alerts import FailureAlerter
from tests.conftest import load, no_sleep

HOOK = "https://hooks.slack.com/services/TFAKE/BFAKE/fake-secret-path-123"
FAIL = {"status": "error", "error": 'events: HTTP 500 from https://api.example.test/logs: {"msg": "boom"} - FAILED after 3 retries'}
OK = {"status": "success"}


class Slack:
    """Records posts; answers 200 'ok' (text/plain) like Slack, or a configured error."""

    def __init__(self, status=200, body="ok"):
        self.posts, self.status, self.body = [], status, body

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.posts.append(json.loads(request.content))
        return httpx.Response(self.status, text=self.body, headers={"content-type": "text/plain"})


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", HOOK)


def alerter(db, slack):
    return FailureAlerter(db, ActionRunner(db, transport=httpx.MockTransport(slack), sleep=no_sleep))


def texts(post):
    return json.dumps(post, ensure_ascii=False)


async def test_one_failing_message_per_streak_then_one_recovered(db, hook):
    slack = Slack()
    a = alerter(db, slack)
    cfg = load("acme_firewall")  # alert_after_failures = 3
    results = [await a.record(cfg, FAIL) for _ in range(5)]
    assert [bool(r) for r in results] == [False, False, True, False, False]
    assert results[2]["channels"] == ["ui", "log", "slack_failure_alert"] and results[2]["failed"] == []
    recovered = await a.record(cfg, OK)
    assert recovered["kind"] == "recovered" and "slack_failure_alert" in recovered["channels"]
    assert len(slack.posts) == 2  # no duplicates for the streak
    failing, back = slack.posts
    assert failing["text"] == "⚠️ Connector failing: Acme Firewall (mock)"
    assert failing["blocks"][0]["text"]["text"] == "⚠️ Connector failing: Acme Firewall (mock)"
    body = texts(failing)
    assert "Failing: 3 runs in a row" in body and "*Last error*" in body and '{\\"msg\\": \\"boom\\"}' in body
    assert failing["blocks"][-1]["elements"][0]["url"] == "http://localhost:8000/app#integrations"
    assert back["text"] == "✅ Connector recovered: Acme Firewall (mock)" and "Healthy again after 5 failed run(s)" in texts(back)
    assert "Last error" not in texts(back)


async def test_a_new_streak_alerts_again(db, hook, monkeypatch):
    from integration_platform import alerts
    clock = iter(f"2026-10-31T10:0{i}:00Z" for i in range(10))  # streaks are minutes apart in real life
    monkeypatch.setattr(alerts, "utcnow", lambda: next(clock))
    slack = Slack()
    a = alerter(db, slack)
    cfg = load("acme_firewall", alert_after_failures=1)
    for _ in range(2):
        await a.record(cfg, FAIL)
        await a.record(cfg, OK)
    assert [p["text"].split(":")[0] for p in slack.posts] == ["⚠️ Connector failing", "✅ Connector recovered"] * 2


async def test_test_message(db, hook):
    slack = Slack()
    r = await alerter(db, slack).send_test()
    assert r == {"sent": ["slack_failure_alert"], "failed": [], "not_configured": []}
    assert slack.posts[0]["text"] == "✅ PlugSec: Slack alerts connected"


async def test_test_message_without_a_webhook(db, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    r = await alerter(db, Slack()).send_test()
    assert r["sent"] == [] and r["not_configured"] == ["slack_failure_alert"]


async def test_slack_rejecting_the_webhook_is_logged_and_shown_not_retried_forever(db, hook, caplog):
    slack = Slack(status=404, body="no_service")
    a = alerter(db, slack)
    cfg = load("acme_firewall", alert_after_failures=1)
    with caplog.at_level(logging.WARNING):
        r = await a.record(cfg, FAIL)
    assert r["channels"] == ["ui", "log"] and r["failed"] and "HTTP 404" in r["failed"][0]
    banner = db.list_notifications(5)[0]["message"]
    assert "Alert delivery failed" in banner and "no_service" in banner
    assert "alert channel slack_failure_alert failed" in caplog.text
    await a.record(cfg, FAIL)  # same streak: no second attempt
    assert len(slack.posts) == 1


async def test_slack_server_errors_retry_a_bounded_number_of_times(db, hook):
    slack = Slack(status=500, body="internal_error")
    r = await alerter(db, slack).record(load("acme_firewall", alert_after_failures=1), FAIL)
    assert len(slack.posts) == 4 and r["failed"]  # 1 attempt + 3 retries (1 s, 2 s, 4 s), then it gives up


async def test_slack_unreachable_does_not_crash(db, hook):
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)
    a = FailureAlerter(db, ActionRunner(db, transport=httpx.MockTransport(down), sleep=no_sleep))
    r = await a.record(load("acme_firewall", alert_after_failures=1), FAIL)
    assert r["kind"] == "failure_alert" and r["failed"] and "connection failed" in r["failed"][0]


async def test_the_webhook_url_never_appears_in_messages_banners_or_logs(db, hook, caplog):
    slack = Slack(status=403, body="invalid_token")
    a = alerter(db, slack)
    with caplog.at_level(logging.INFO):
        await a.record(load("acme_firewall", alert_after_failures=1), FAIL)
        await a.send_test()
    stored = json.dumps(db.list_notifications(10)) + json.dumps(db.list_action_results())
    for where in (stored, caplog.text, json.dumps(slack.posts)):
        assert "fake-secret-path-123" not in where and "hooks.slack.com/services/TFAKE" not in where
