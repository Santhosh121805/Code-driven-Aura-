"""FR-9 bad data: malformed records are quarantined per stream with a reason; the run continues and stores the rest."""
import random

import httpx
import pytest

from integration_platform.engine import dry_run_integration, run_integration
from integration_platform.normaliser import BadRecord, normalise
from tests.fakes import mock_cloudtrail, mock_firewall, mock_okta
from tests.conftest import load, no_sleep, okta_config, only


def good(i: int) -> dict:
    return {"eventID": f"ct-{i}", "eventName": "GetObject", "eventSource": "s3.amazonaws.com", "eventTime": "2026-10-31T05:49:32Z",
            "userIdentity": {"arn": "arn:aws:iam::491085362710:user/priya.sharma"}, "sourceIPAddress": "10.0.4.23"}


def stream():
    return load("aws_cloudtrail").streams[0]


@pytest.mark.parametrize("broken,reason", [
    ({k: v for k, v in good(1).items() if k != "eventID"}, "missing required field id ('eventID' not found in record)"),
    ({**good(1), "eventTime": "not-a-timestamp"}, "unparseable time 'not-a-timestamp' in 'eventTime' (expected iso8601)"),
    ({**good(1), "userIdentity": {"arn": {"truncated": True}}}, "wrong type for user: 'userIdentity.arn' is an object, expected a single value"),
    ({**good(1), "sourceIPAddress": ["10.0.0.1", "10.0.0.2"]}, "wrong type for src_ip: 'sourceIPAddress' is a list, expected a single value"),
    ("just a string", "record is not a JSON object (got str)"),
])
def test_bad_records_are_rejected_with_a_clear_reason(broken, reason):
    with pytest.raises(BadRecord) as exc:
        normalise(broken, stream(), "aws_cloudtrail")
    assert str(exc.value) == reason


def test_bad_users_and_devices():
    with pytest.raises(BadRecord, match="unparseable time 'last tuesday'"):
        normalise({"id": "u", "lastLogin": "last tuesday", "profile": {}}, load("mock_okta").stream("users"), "mock_okta")
    with pytest.raises(BadRecord, match="missing required field id"):
        normalise({"hostname": "x", "last_seen": 1793425772}, only("acme_firewall", "devices").streams[0], "acme_firewall")
    with pytest.raises(BadRecord, match="wrong type for email"):
        normalise({"id": "u", "profile": {"email": ["a@b.in", "c@d.in"]}}, load("mock_okta").stream("users"), "mock_okta")


def test_required_fields_are_configurable():
    s = load("aws_cloudtrail", stream={"required_fields": ["id", "timestamp", "user"]}).streams[0]
    with pytest.raises(BadRecord, match="missing required field user"):
        normalise({**good(1), "userIdentity": {}}, s, "x")
    relaxed = load("aws_cloudtrail", stream={"required_fields": []}).streams[0]
    assert normalise({k: v for k, v in good(1).items() if k != "eventTime"}, relaxed, "x")["timestamp"].endswith("Z")


async def test_run_quarantines_and_continues(db):
    body = {"Records": [good(1), {**good(2), "eventTime": "garbage"}, good(3), {"eventName": "x"}, good(4)]}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    result = await run_integration(load("aws_cloudtrail"), db, transport=transport, sleep=no_sleep)
    assert result["status"] == "success"
    assert (result["records_fetched"], result["records_new"], result["quarantined"]) == (5, 3, 2)
    assert result["streams"][0]["note"] == "2 of 5 invalid (quarantined)"
    rows = db.list_quarantine("aws_cloudtrail")
    assert len(rows) == 2 and {r["stream"] for r in rows} == {"events"} and {r["entity"] for r in rows} == {"event"}
    assert rows[0]["raw"] == {"eventName": "x"}
    run = db.recent_runs("aws_cloudtrail")[0]
    assert run["status"] == "success" and run["records_quarantined"] == 2
    assert db.get_last_sync("aws_cloudtrail:events")  # sync advanced: one bad record does not block the feed


async def test_quarantine_is_per_stream(db, firewall, monkeypatch):
    """A malformed device does not affect the logs stream of the same connector."""
    original = mock_firewall.device
    monkeypatch.setattr(mock_firewall, "device", lambda i: {**original(i), "last_seen": "never"} if i == 3 else original(i))
    result = await run_integration(load("acme_firewall"), db, transport=firewall, sleep=no_sleep)
    logs, devices = result["streams"]
    assert (logs["quarantined"], devices["quarantined"]) == (0, 1) and devices["new"] == 14 and logs["new"] == 12
    assert db.list_quarantine("acme_firewall")[0]["stream"] == "devices"


async def test_dry_run_reports_quarantined_sample_records():
    body = {"Records": [good(1), {**good(2), "eventTime": "garbage"}]}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    r = await dry_run_integration(load("aws_cloudtrail"), transport=transport)
    assert len(r["normalised"]) == 1 and r["quarantined"][0]["reason"].startswith("unparseable time 'garbage'")


@pytest.mark.parametrize("mock,maker,stream_factory", [
    (mock_cloudtrail, lambda: mock_cloudtrail.record(), lambda: load("aws_cloudtrail").streams[0]),
    (mock_firewall, mock_firewall._log, lambda: only("acme_firewall", "logs").streams[0]),
    (mock_okta, mock_okta.event, lambda: okta_config().streams[0]),
])
def test_every_mock_malform_kind_is_quarantined(mock, maker, stream_factory):
    s = stream_factory()
    sample = maker()
    normalise(sample, s, "x")
    for kind in ("missing_id", "bad_time", "wrong_type"):
        with pytest.raises(BadRecord):
            normalise(mock.malform(sample, kind), s, "x")


def test_device_and_user_malformers_are_quarantined():
    dev, usr = only("acme_firewall", "devices").streams[0], load("mock_okta").stream("users")
    for kind in ("missing_id", "bad_time", "wrong_type"):
        with pytest.raises(BadRecord):
            normalise(mock_firewall.malform_device(mock_firewall.device(1), kind), dev, "x")
        with pytest.raises(BadRecord):
            normalise(mock_okta.malform_user(mock_okta.user(1), kind), usr, "x")


async def test_mocks_emit_malformed_records_about_1_in_15(monkeypatch, db, firewall):
    monkeypatch.setenv("MALFORMED_RECORDS", "on")
    random.seed(7)
    cfg = only("acme_firewall", "logs")
    total = quarantined = 0
    for _ in range(25):  # 25 runs x 12 records = 300 records
        r = await run_integration(cfg, db, transport=firewall, sleep=no_sleep)
        total += r["records_fetched"]
        quarantined += r["quarantined"]
    assert total == 300 and 8 <= quarantined <= 40
