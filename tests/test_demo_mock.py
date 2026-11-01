"""Demo controls that need the Demo source (Mock): 429s, Retry-After, malformed record, bulk export -> pause + ticket."""
import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

from fastapi.testclient import TestClient

from integration_platform import api, auth, config, demo, demo_mock, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.engine import GUARD_SOURCE
from integration_platform.vault import Vault
from tests.conftest import SleepRecorder, load, signed_in
from tests.fakes import mock_jira

recorder = SleepRecorder()
mock_app = FastAPI()
mock_app.include_router(demo_mock.router)


@pytest.fixture
def registry(db, tmp_path, monkeypatch, jira):
    monkeypatch.setattr(config, "INTEGRATIONS_DIR", tmp_path)
    monkeypatch.setattr(scheduler, "INTEGRATIONS_DIR", tmp_path)
    demo_mock.reset()
    recorder.delays.clear()
    reg = scheduler.Registry(db, ActionRunner(db, transport=jira, sleep=recorder), Vault(db, Fernet.generate_key().decode()))
    reg.transport = httpx.ASGITransport(app=mock_app)
    reg.sleep = recorder
    reg.integrations = {"demo_mock": load("demo_mock")}
    yield reg
    demo_mock.reset()
    config.set_secret_lookup(None)


def test_mock_is_off_by_default_and_labelled():
    cfg = load("demo_mock")
    assert cfg.enabled is False and "Mock" in cfg.display_name


async def test_two_429s_then_recovered(registry):
    r = await demo.trigger_429(registry)
    assert (r["status"], r["retries"], r["records_fetched"]) == ("success", 2, 12 + 10)  # events + mock devices


async def test_retry_after_waits_exactly_5s(registry):
    r = await demo.trigger_retry_after(registry)
    assert r["status"] == "success" and r["retries"] == 1 and recorder.delays == [5]
    assert "HTTP 429: waited 5s due to Retry-After" in r["retry_log"]


async def test_malformed_record_is_quarantined_and_run_continues(registry, db):
    r = await demo.trigger_malformed(registry)
    assert (r["status"], r["quarantined"], r["records_new"]) == ("success", 1, 11 + 10)  # 11 events + 10 mock devices
    assert db.list_quarantine("demo_mock")[0]["reason"].startswith("unparseable time")


async def test_bulk_export_pauses_the_mock_and_opens_one_ticket(registry, db):
    r = await demo.simulate_bulk_export(registry)
    assert r["baseline_warmup_runs"] == 3 and r["status"] == "suspicious"
    assert db.get_state("demo_mock")["state"] == "suspicious"
    tickets = [t["summary"] for t in mock_jira._tickets]
    assert len(tickets) == 1 and tickets[0].startswith("[CRITICAL] Possible token abuse: abnormal data volume from Demo source (Mock): ")
    with pytest.raises(demo.DemoError, match="suspicious"):
        await demo.trigger_malformed(registry)  # a paused mock is not silently re-run


async def test_guard_alert_on_a_mock_is_a_platform_event_shown_in_the_live_views(registry, db, monkeypatch):
    """The mock's own data stays hidden from Events / Overview, but the guard's alert about it is PlugSec's: always shown."""
    r = await demo.simulate_bulk_export(registry)
    s = r["suspicious"]
    event = db.get_event(GUARD_SOURCE, s["event_id"])
    assert event["resource"] == "demo_mock" and event["raw"]["connector"] == "demo_mock" and event["raw"]["connector_name"] == "Demo source (Mock)"
    assert event["description"] == (f"Possible token abuse: abnormal data volume from Demo source (Mock): "
                                    f"{s['records']:,} records vs baseline {s['baseline']:,g}")
    assert event["ticket_key"] and len(mock_jira._tickets) == 1  # one Jira ticket for the one event
    monkeypatch.setattr(api.state, "db", db, raising=False)
    monkeypatch.setattr(api.state, "registry", registry, raising=False)
    auth._failures.clear()
    c = signed_in(TestClient(api.app), "viewer")
    assert api.mock_sources() == ("demo_mock",)
    events = c.get("/api/events").json()["items"]
    assert [e["source"] for e in events] == [GUARD_SOURCE]  # the mock's own events are hidden, the alert is not
    assert c.get("/api/events", params={"severity": "critical", "since": "2000-01-01T00:00:00Z"}).json()["total"] == 1  # Recent critical
    st = c.get("/api/stats").json()
    assert st["last_24h"]["by_severity"]["critical"] == 1 and st["critical"] == 1 and st["last_24h"]["tickets"] == 1
    detail = c.get("/api/integrations/demo_mock").json()
    assert detail["health"]["status"] == "suspicious" and detail["guard_event"]["id"] == s["event_id"]


def test_old_guard_events_move_to_the_platform_source(tmp_path):
    from integration_platform.db import Database
    db = Database(tmp_path / "old.db")
    db.store({"entity": "event", "source": "demo_mock", "stream": "exfiltration_guard", "id": "guard-7", "type": "token_abuse",
              "severity": "critical", "timestamp": "2026-11-01T00:00:00Z", "description": "x", "fetched_at": "2026-11-01T00:00:00Z", "raw": {}})
    db._conn.close()
    moved = Database(tmp_path / "old.db").get_event(GUARD_SOURCE, "guard-7")
    assert moved and moved["resource"] == "demo_mock"


async def test_mock_events_never_exceed_medium_and_are_labelled(registry, db):
    await registry.run_now("demo_mock", wait=True)
    events, _ = db.list_records("event", "demo_mock")
    assert events and {e["severity"] for e in events} <= {"info", "low", "medium"}
    assert all(e["description"].startswith("[Mock]") for e in events)


def test_reset_keeps_the_mock_but_never_enables_it(registry):
    registry.integrations["demo_mock"] = registry.integrations["demo_mock"].model_copy(update={"enabled": False})
    registry.reset_demo()
    assert "demo_mock" in registry.integrations and registry.integrations["demo_mock"].enabled is False


async def test_mock_device_inventory_fills_the_devices_table(registry, db):
    await registry.run_now("demo_mock", wait=True)
    await registry.run_now("demo_mock", wait=True)  # re-runs update the same devices
    devices, total = db.list_records("device", "demo_mock")
    assert total == 10 and all(d["hostname"] and d["ip"] and d["os"] and d["owner"] and d["last_seen"] for d in devices)
