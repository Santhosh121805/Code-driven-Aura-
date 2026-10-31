"""Demo controls that need the Demo source (Mock): 429s, Retry-After, malformed record, bulk export -> pause + ticket."""
import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

from integration_platform import config, demo, demo_mock, scheduler
from integration_platform.actions import ActionRunner
from integration_platform.vault import Vault
from tests.conftest import SleepRecorder, load
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
    assert (r["status"], r["retries"], r["records_fetched"]) == ("success", 2, 12)


async def test_retry_after_waits_exactly_5s(registry):
    r = await demo.trigger_retry_after(registry)
    assert r["status"] == "success" and r["retries"] == 1 and recorder.delays == [5]
    assert "HTTP 429: waited 5s due to Retry-After" in r["retry_log"]


async def test_malformed_record_is_quarantined_and_run_continues(registry, db):
    r = await demo.trigger_malformed(registry)
    assert (r["status"], r["quarantined"], r["records_new"]) == ("success", 1, 11)
    assert db.list_quarantine("demo_mock")[0]["reason"].startswith("unparseable time")


async def test_bulk_export_pauses_the_mock_and_opens_one_ticket(registry, db):
    r = await demo.simulate_bulk_export(registry)
    assert r["baseline_warmup_runs"] == 3 and r["status"] == "suspicious"
    assert db.get_state("demo_mock")["state"] == "suspicious"
    tickets = [t["summary"] for t in mock_jira._tickets]
    assert tickets == ["[CRITICAL] Possible token abuse: abnormal data volume from Demo source (Mock)"]  # only the guard alert
    with pytest.raises(demo.DemoError, match="suspicious"):
        await demo.trigger_malformed(registry)  # a paused mock is not silently re-run


async def test_mock_events_never_exceed_medium_and_are_labelled(registry, db):
    await registry.run_now("demo_mock", wait=True)
    events, _ = db.list_records("event", "demo_mock")
    assert events and {e["severity"] for e in events} <= {"info", "low", "medium"}
    assert all(e["description"].startswith("[Mock]") for e in events)


def test_reset_keeps_the_mock_but_never_enables_it(registry):
    registry.integrations["demo_mock"] = registry.integrations["demo_mock"].model_copy(update={"enabled": False})
    registry.reset_demo()
    assert "demo_mock" in registry.integrations and registry.integrations["demo_mock"].enabled is False
