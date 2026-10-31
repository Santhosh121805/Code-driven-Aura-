"""No duplicates: unique (source, entity, id). Events insert once; users/devices refresh in place. One ticket per event."""
import httpx

from integration_platform.actions import ActionRunner
from integration_platform.engine import run_integration
from mocks import mock_jira
from tests.conftest import load, no_sleep

FIXED = {"Records": [
    {"eventID": "ct-1", "eventName": "DeleteTrail", "eventSource": "cloudtrail.amazonaws.com", "eventTime": "2026-10-31T05:49:32Z",
     "sourceIPAddress": "45.155.205.233", "userIdentity": {"arn": "arn:aws:iam::491085362710:user/svc.backup"}},
    {"eventID": "ct-2", "eventName": "GetObject", "eventSource": "s3.amazonaws.com", "eventTime": "2026-10-31T05:50:00Z",
     "sourceIPAddress": "10.0.4.23", "userIdentity": {"arn": "arn:aws:iam::491085362710:user/priya.sharma"}},
]}


def fixed_transport():
    return httpx.MockTransport(lambda request: httpx.Response(200, json=FIXED))


async def test_same_events_are_stored_once(db):
    cfg = load("aws_cloudtrail")
    first = await run_integration(cfg, db, transport=fixed_transport(), sleep=no_sleep)
    second = await run_integration(cfg, db, transport=fixed_transport(), sleep=no_sleep)
    assert (first["records_new"], second["records_new"]) == (2, 0)
    assert second["records_fetched"] == 2
    assert db.list_records("event")[1] == 2


async def test_users_and_devices_are_refreshed_not_duplicated(db, okta, firewall):
    cfg_okta, cfg_fw = load("mock_okta"), load("acme_firewall")
    r1 = await run_integration(cfg_okta, db, transport=okta, sleep=no_sleep)
    r2 = await run_integration(cfg_okta, db, transport=okta, sleep=no_sleep)
    users1, users2 = r1["streams"][0], r2["streams"][0]
    assert (users1["new"], users2["new"], users2["updated"]) == (10, 0, 10)
    assert db.counts()["users"]["total"] == 10
    await run_integration(cfg_fw, db, transport=firewall, sleep=no_sleep)
    await run_integration(cfg_fw, db, transport=firewall, sleep=no_sleep)
    assert db.counts()["devices"]["total"] == 15


async def test_incremental_sync_stores_last_sync_per_stream(db):
    cfg = load("aws_cloudtrail")
    assert db.get_last_sync("aws_cloudtrail:events") is None
    await run_integration(cfg, db, transport=fixed_transport(), sleep=no_sleep)
    assert db.get_last_sync("aws_cloudtrail:events").endswith("Z")


async def test_last_sync_is_sent_on_the_next_run(db):
    seen = []

    def handler(request):
        seen.append(request.url.params.get("StartTime"))
        return httpx.Response(200, json=FIXED)
    cfg = load("aws_cloudtrail")
    await run_integration(cfg, db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    await run_integration(cfg, db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert seen[0] is None and seen[1] == db.get_last_sync("aws_cloudtrail:events")


async def test_action_fires_once_per_event_and_links_ticket(db, jira):
    runner = ActionRunner(db, transport=jira, sleep=no_sleep)
    cfg = load("aws_cloudtrail")
    await run_integration(cfg, db, on_new_event=runner.handle, transport=fixed_transport(), sleep=no_sleep)
    await run_integration(cfg, db, on_new_event=runner.handle, transport=fixed_transport(), sleep=no_sleep)
    assert len(mock_jira._tickets) == 1
    ticket = mock_jira._tickets[0]
    assert ticket["key"] == "SOC-1"
    assert ticket["summary"] == "[CRITICAL] DeleteTrail (cloudtrail.amazonaws.com) on 45.155.205.233"
    events = {e["id"]: e for e in db.list_records("event")[0]}
    assert events["ct-1"]["ticket_key"] == "SOC-1" and events["ct-2"]["ticket_key"] is None
    again = await runner.fire(runner.actions["create_jira_ticket"], events["ct-1"])
    assert again["status"] == "duplicate" and len(mock_jira._tickets) == 1


async def test_cve_intel_sources_do_not_create_tickets(db, jira):
    runner = ActionRunner(db, transport=jira, sleep=no_sleep)
    event = {"source": "nvd", "id": "CVE-2026-1", "severity": "critical", "description": "x", "timestamp": "t"}
    assert await runner.handle(event) == []  # action is scoped to incident sources (source_in)


async def test_failed_action_is_recorded_and_never_retried_into_a_duplicate(db):
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        return httpx.Response(500, json={})
    runner = ActionRunner(db, transport=httpx.MockTransport(flaky), sleep=no_sleep)
    event = {"source": "aws_cloudtrail", "id": "ct-9", "severity": "critical", "description": "x", "host": "h", "timestamp": "t"}
    result = await runner.fire(runner.actions["create_jira_ticket"], event)
    assert result["status"] == "failed" and "HTTP 500" in result["error"]
    assert calls["n"] == 4  # 1 attempt + 3 retries (1s, 2s, 4s)
    assert db.list_action_results()[0]["status"] == "failed"
    assert (await runner.fire(runner.actions["create_jira_ticket"], event))["status"] == "duplicate"


async def test_body_template_escapes_quotes(db, jira):
    runner = ActionRunner(db, transport=jira, sleep=no_sleep)
    event = {"source": "acme_firewall", "id": "7", "severity": "high", "description": 'He said "hi" \\ bye', "host": None,
             "src_ip": "10.0.0.1", "timestamp": "t"}
    result = await runner.fire(runner.actions["create_jira_ticket"], event)
    assert result["status"] == "success"
    assert mock_jira._tickets[-1]["summary"] == '[HIGH] He said "hi" \\ bye on 10.0.0.1'
