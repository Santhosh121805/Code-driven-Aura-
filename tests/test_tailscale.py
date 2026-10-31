"""Tailscale (real device source) through config only: devices, client-update and key-expiry events from the same
response, and "New device joined" the first time a device id appears. A fake answers like GET /api/v2/tailnet/-/devices."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from integration_platform.config import ConfigError, validate_integration
from integration_platform.engine import run_integration
from tests.conftest import load, no_sleep

TOKEN = "tskey-api-test-not-real"


def iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def device(n, **extra):
    d = {"id": f"{n}000", "nodeId": f"n{n}CNTRL", "hostname": f"host-{n}", "name": f"host-{n}.tail1234.ts.net",
         "addresses": [f"100.64.0.{n}", f"fd7a:115c:a1e0::{n}"], "os": ["windows", "linux", "iOS"][n % 3], "user": "me@example.com",
         "clientVersion": "1.80.0", "updateAvailable": False, "lastSeen": iso(timedelta(minutes=-1)),
         "expires": iso(timedelta(days=120)), "keyExpiryDisabled": False, "authorized": True}
    d.update(extra)
    return d


class Tailnet:
    def __init__(self, devices):
        self.devices, self.auth = devices, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.auth.append(request.headers.get("Authorization"))
        if request.url.path != "/api/v2/tailnet/-/devices":
            return httpx.Response(404, json={"message": "not found"})
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"message": "API token invalid"})
        return httpx.Response(200, json={"devices": self.devices})


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("tailscale_token", TOKEN)


def base_devices():
    return [device(1),
            device(2, updateAvailable=True, clientVersion="1.76.1"),
            device(3, expires=iso(timedelta(days=3)), lastSeen=iso(timedelta(hours=-2))),
            device(4, expires="0001-01-01T00:00:00Z", keyExpiryDisabled=True),          # never expires: no event
            device(5, expires=iso(timedelta(days=-2)))]                                   # already expired: not "soon"


def test_config_is_real_and_config_only():
    cfg = load("tailscale")
    assert (cfg.base_url, cfg.auth.type, cfg.schedule_seconds) == ("https://api.tailscale.com", "bearer", 60)
    assert [s.name for s in cfg.streams] == ["devices", "update_available", "key_expiry"]
    assert all(s.endpoint == "/api/v2/tailnet/-/devices" and s.pagination.type == "none" for s in cfg.streams)


async def test_devices_events_and_new_device_detection(db, token):
    api = Tailnet(base_devices())
    r = await run_integration(load("tailscale"), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    assert r["status"] == "success" and set(api.auth) == {f"Bearer {TOKEN}"}
    assert [(s["name"], s["fetched"]) for s in r["streams"]] == [("devices", 5), ("update_available", 1), ("key_expiry", 1)]
    devices = {d["hostname"]: d for d in db.list_records("device", "tailscale")[0]}
    d1 = devices["host-1"]
    assert (d1["id"], d1["ip"], d1["os"], d1["owner"]) == ("n1CNTRL", "100.64.0.1", "linux", "me@example.com")
    assert d1["last_seen"].endswith("Z") and d1["raw"]["name"] == "host-1.tail1234.ts.net"  # raw kept
    events = {e["type"]: e for e in db.list_records("event", "tailscale", limit=50)[0] if e["type"] != "device_joined"}
    assert events["client_update_available"]["severity"] == "low" and "host-2" in events["client_update_available"]["description"]
    assert events["device_key_expiring"]["severity"] == "medium" and events["device_key_expiring"]["host"] == "host-3"
    joined = [e for e in db.list_records("event", "tailscale", limit=50)[0] if e["type"] == "device_joined"]
    assert len(joined) == 5 and {e["severity"] for e in joined} == {"info"}
    assert next(e for e in joined if e["host"] == "host-1")["description"] == "New device joined: host-1 (linux) by me@example.com"


async def test_new_device_event_only_once_and_for_a_new_id(db, token):
    api = Tailnet(base_devices())
    await run_integration(load("tailscale"), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    r = await run_integration(load("tailscale"), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    assert r["records_new"] == 0  # same devices, same versions, same keys: nothing new, no duplicate events
    api.devices.append(device(6, hostname="new-laptop", os="macOS", user="alice@example.com"))
    r = await run_integration(load("tailscale"), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    joined = [e for e in db.list_records("event", "tailscale", type_="device_joined", limit=50)[0]]
    assert len(joined) == 6 and joined[0]["description"] == "New device joined: new-laptop (macOS) by alice@example.com"
    assert r["streams"][0]["new_events"] == 1


async def test_actions_see_the_new_device_event(db, token):
    seen = []

    async def on_event(e):
        seen.append(e["type"])
    await run_integration(load("tailscale"), db, on_new_event=on_event, transport=httpx.MockTransport(Tailnet([device(1)])), sleep=no_sleep)
    assert seen == ["device_joined"]


async def test_wrong_token_is_auth_failed(db, monkeypatch):
    monkeypatch.setenv("tailscale_token", "wrong")
    r = await run_integration(load("tailscale"), db, transport=httpx.MockTransport(Tailnet([device(1)])), sleep=no_sleep)
    assert r["status"] == "error" and "Authentication failed: HTTP 401" in r["error"]


def test_new_record_event_template_is_checked():
    data = load("tailscale").model_dump(mode="json", exclude_none=True)
    data["streams"][0]["new_record_event"]["description"] = "{{ secret }} joined"
    with pytest.raises(ConfigError, match="new_record_event uses secret"):
        validate_integration(data)
    data = load("tailscale").model_dump(mode="json", exclude_none=True)
    data["streams"][1]["new_record_event"] = {"description": "x"}
    with pytest.raises(ConfigError, match="events are already events"):
        validate_integration(data)


def test_days_until():
    from integration_platform.normaliser import search
    assert 2.9 < search("days_until(t)", {"t": iso(timedelta(days=3))}) <= 3
    assert search("days_until(t)", {"t": "not a time"}) is None
