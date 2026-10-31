"""Integration catalog: every template is valid and safe, statuses and the gap table add up, and two templates
(Fortinet FortiGate, Lacework FortiCNAPP) run end to end against MOCKs shaped like the vendors' documented responses."""
import re
import types

import httpx
import pytest
from fastapi.testclient import TestClient

from integration_platform import api, catalog
from integration_platform.config import ENV_REF_ANY, validate_integration
from integration_platform.engine import clear_oauth_cache, run_integration
from tests.conftest import ROOT, no_sleep, signed_in
from tests.fakes import mock_fortigate, mock_lacework

ENTRIES = catalog.load_entries()
BY_ID = {e["id"]: e for e in ENTRIES}


def test_catalog_has_all_35_tools_with_complete_research_notes():
    assert len(ENTRIES) == 35
    for e in ENTRIES:
        m = e["catalog"]
        assert m["category"] in catalog.CATEGORIES, e["id"]
        assert m["verification"] in ("verified", "partial", "unverified"), e["id"]
        assert all(n in catalog.CAPABILITIES for n in m["needs"]), e["id"]
        for field in ("name", "api_style", "auth", "paging", "endpoint", "notes"):
            assert m[field], (e["id"], field)
        assert m["docs"].startswith("https://") or (not m["docs"] and m["api_style"].startswith("none public")), e["id"]
        if m["verification"] == "unverified":
            assert e["template"] is None, f"{e['id']}: no template may rest on unverified facts"


def test_templates_are_valid_safe_and_not_active():
    templates = [e for e in ENTRIES if e["template"]]
    assert {e["id"] for e in templates} == {"fortinet_fortigate", "lacework_forticnapp", "trend_micro_vision_one", "netskope_dlp", "sophos_intercept_x"}
    active = {p.stem for p in (ROOT / "configs" / "integrations").glob("*.yaml")}
    for e in templates:
        assert e["template_error"] is None, e["template_error"]
        cfg = validate_integration(e["template"])  # same model as a real integration
        assert ENV_REF_ANY.search(cfg.base_url), f"{e['id']}: base URL must come from .env"
        assert cfg.name not in active, f"{e['id']} must stay a template"
        text = (ROOT / "catalog" / f"{e['id']}.yaml").read_text(encoding="utf-8")
        assert not re.search(r"(token|secret|password|api_key|key)\s*:\s*[\"']?(?!\$\{)[A-Za-z0-9_\-]{12,}", text, re.I), e["id"]


def test_status_counts_and_gap_table():
    view = catalog.catalog_view(set())
    assert view["counts"] == {"connected": 0, "template_ready": 5, "needs_verification": 10, "needs_capability": 16, "no_public_api": 4}
    gaps = {g["capability"]: g for g in view["gaps"]}
    assert gaps["session_login"]["implemented"] and gaps["session_login"]["count"] == 8
    assert gaps["body_pagination"]["count"] == 7 and not gaps["body_pagination"]["implemented"]
    assert sum(view["counts"].values()) == 35
    assert catalog.catalog_view({"fortinet_fortigate"})["counts"]["connected"] == 1  # an active integration with that name


def test_catalog_api_is_readable_by_every_role(db, monkeypatch):
    monkeypatch.setattr(api.state, "db", db, raising=False)
    monkeypatch.setattr(api.state, "registry", types.SimpleNamespace(integrations={}), raising=False)
    for role in ("viewer", "analyst", "admin"):
        data = signed_in(TestClient(api.app), role).get("/api/catalog").json()
        assert len(data["entries"]) == 35 and data["gaps"]
    assert TestClient(api.app).get("/api/catalog").status_code == 401


# ---------------------------------------------------------------- live proof against MOCKs
@pytest.fixture
def fortigate_env(monkeypatch):
    monkeypatch.setenv("FORTIGATE_HOST", "fgt.test")
    monkeypatch.setenv("fortigate_token", mock_fortigate.TOKEN)


async def test_mock_fortigate_template_end_to_end(db, fortigate_env):
    tpl = dict(BY_ID["fortinet_fortigate"]["template"])
    tpl["streams"] = [{**tpl["streams"][0], "pagination": {**tpl["streams"][0]["pagination"], "limit": 3}}]  # force paging
    cfg = validate_integration(tpl)
    r = await run_integration(cfg, db, transport=httpx.ASGITransport(app=mock_fortigate.app), sleep=no_sleep)
    assert (r["status"], r["records_fetched"], r["pages"], r["quarantined"]) == ("success", 7, 3, 0)
    events, _ = db.list_records("event", "fortinet_fortigate")
    by_desc = {e["type"]: e for e in events}
    assert by_desc["Admin login failed"]["severity"] == "critical" and by_desc["Admin login failed"]["src_ip"] == "203.0.113.9"
    assert by_desc["FortiGuard update failed"]["severity"] == "high"
    assert by_desc["Admin login successful"]["timestamp"] == "2026-10-31T10:15:02Z" and by_desc["Admin login successful"]["host"] == "FGT-HQ"


async def test_mock_fortigate_wrong_token_is_auth_failed(db, fortigate_env, monkeypatch):
    monkeypatch.setenv("fortigate_token", "wrong")
    r = await run_integration(validate_integration(BY_ID["fortinet_fortigate"]["template"]), db,
                              transport=httpx.ASGITransport(app=mock_fortigate.app), sleep=no_sleep)
    assert r["status"] == "error" and "Authentication failed: HTTP 401" in r["error"]


@pytest.fixture
def lacework_env(monkeypatch):
    clear_oauth_cache()
    mock_lacework.reset()
    monkeypatch.setenv("LACEWORK_ACCOUNT", "acme")
    monkeypatch.setenv("lacework_secret", mock_lacework.SECRET)
    monkeypatch.setenv("LACEWORK_KEY_ID", mock_lacework.KEY_ID)
    yield
    clear_oauth_cache()


async def test_mock_lacework_template_end_to_end_with_session_login(db, lacework_env):
    cfg = validate_integration(BY_ID["lacework_forticnapp"]["template"])
    transport = httpx.ASGITransport(app=mock_lacework.app)
    r = await run_integration(cfg, db, transport=transport, sleep=no_sleep)
    assert (r["status"], r["records_fetched"], r["pages"]) == ("success", 3, 2)
    assert mock_lacework.state["logins"] == 1  # one login, the token reused for both pages
    events = {e["id"]: e for e in db.list_records("event", "lacework_forticnapp")[0]}
    assert events["103"]["severity"] == "critical" and events["101"]["description"] == "Root account used"
    start, end = mock_lacework.state["queries"][0]
    assert start < end and start.endswith("Z")  # first run: the last day
    await run_integration(cfg, db, transport=transport, sleep=no_sleep)
    assert mock_lacework.state["logins"] == 1 and mock_lacework.state["queries"][1][0] == db.get_last_sync("lacework_forticnapp:alerts")


async def test_mock_lacework_wrong_secret_fails_at_login(db, lacework_env, monkeypatch):
    monkeypatch.setenv("lacework_secret", "wrong")
    r = await run_integration(validate_integration(BY_ID["lacework_forticnapp"]["template"]), db,
                              transport=httpx.ASGITransport(app=mock_lacework.app), sleep=no_sleep)
    assert r["status"] == "error" and "Authentication failed: HTTP 401" in r["error"] and "/api/v2/access/tokens" in r["error"]
