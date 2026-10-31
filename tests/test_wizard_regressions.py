"""Regressions: URL joining never doubles a slash; a new wizard draft starts clean; live views leave labelled mocks out."""
import re
import types

import httpx
import pytest
from fastapi.testclient import TestClient

from integration_platform import api, auth
from integration_platform.config import join_url, validate_integration
from integration_platform.db import Database
from integration_platform.engine import _Request, run_integration
from tests.conftest import ROOT, no_sleep, signed_in

APP_JS = (ROOT / "integration_platform" / "static" / "app.js").read_text(encoding="utf-8")


@pytest.mark.parametrize("base,path,url", [
    ("https://api.github.com", "/user", "https://api.github.com/user"),
    ("https://api.github.com/", "/user", "https://api.github.com/user"),
    ("https://api.github.com//", "//user", "https://api.github.com/user"),
    ("https://host/api", "/v1/x", "https://host/api/v1/x"),
    ("https://hooks.example.test/services/T/B/X", "", "https://hooks.example.test/services/T/B/X"),
])
def test_join_url_has_exactly_one_slash(base, path, url):
    assert join_url(base, path) == url


def cfg(base_url, endpoint):
    return validate_integration({"name": "kev", "display_name": "KEV", "base_url": base_url, "auth": {"type": "none"},
                                 "streams": [{"name": "kev", "endpoint": endpoint, "mapping": {"id": "cveID"}}]})


def test_the_reported_double_slash_is_gone(monkeypatch):
    c = cfg("https://api.github.com/", "//sites/default/files/feeds/kev.json")  # a slash typed after a pre-filled "/"
    assert c.base_url == "https://api.github.com" and c.streams[0].endpoint == "/sites/default/files/feeds/kev.json"
    assert _Request(c, c.streams[0]).url == "https://api.github.com/sites/default/files/feeds/kev.json"
    monkeypatch.setenv("KEV_HOST", "https://www.cisa.gov/")  # a setting with a trailing slash
    c = cfg("${KEV_HOST}", "/sites/x.json")
    assert _Request(c, c.streams[0]).url == "https://www.cisa.gov/sites/x.json"


async def test_requests_go_to_the_single_slash_url(db):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=[{"cveID": "CVE-1"}])
    await run_integration(cfg("https://www.cisa.gov/", "//feeds/kev.json"), db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert seen == ["https://www.cisa.gov/feeds/kev.json"]


def test_endpoint_must_still_start_with_a_slash():
    from integration_platform.config import ConfigError
    with pytest.raises(ConfigError, match="must start with '/'"):
        cfg("https://x.test", "feeds/kev.json")


# ---- wizard draft (the UI logic lives in app.js; the browser check is in the README run notes)
def test_a_new_endpoint_starts_with_an_empty_path():
    new_stream = re.search(r"const newStream = .*?\}\);", APP_JS, re.S).group(0)
    assert 'endpoint: ""' in new_stream and 'endpoint: "/"' not in new_stream


def test_add_integration_starts_a_clean_draft_and_restores_only_with_a_notice():
    assert re.search(r"closest\('a\[href=\"#wizard\"\]'\).*?state\.freshWizard = true", APP_JS, re.S)  # sidebar link and button
    show = re.search(r'if \(nav\.page === "wizard"\) \{.*?\n  \}', APP_JS, re.S).group(0)
    assert "startFreshWizard()" in show and "noteRestoredDraft()" in show
    assert "Draft restored:" in APP_JS and 'data-draft="fresh">Start fresh' in APP_JS and "Restore it" in APP_JS
    template = re.search(r"function useTemplate\(id\) \{.*?\n\}", APP_JS, re.S).group(0)
    assert "freshWizard" not in template and "Template loaded" in template  # templates prefill on purpose


def test_base_url_hint_for_a_path_or_trailing_slash():
    assert "function baseUrlHint(url)" in APP_JS and "The base URL has a path" in APP_JS and "trailing slash is removed" in APP_JS


# ---- live views: no mocks
@pytest.fixture
def live(tmp_path, monkeypatch):
    database = Database(tmp_path / "live.db")
    monkeypatch.setattr(api.state, "db", database, raising=False)
    regs = {"tailscale": types.SimpleNamespace(display_name="Tailscale"), "demo_mock": types.SimpleNamespace(display_name="Demo source (Mock)")}
    monkeypatch.setattr(api.state, "registry", types.SimpleNamespace(integrations=regs), raising=False)
    auth._failures.clear()
    for src in ("tailscale", "demo_mock"):
        database.store({"entity": "device", "source": src, "stream": "devices", "id": f"{src}-1", "hostname": f"{src}-host",
                        "fetched_at": "2026-11-01T00:00:00Z", "raw": {}})
        database.store({"entity": "event", "source": src, "stream": "events", "id": f"{src}-e", "type": "t", "severity": "critical",
                        "timestamp": "2099-01-01T00:00:00Z", "description": "x", "fetched_at": "2026-11-01T00:00:00Z", "raw": {}})
    return database


def test_live_views_leave_labelled_mocks_out(live):
    c = signed_in(TestClient(api.app), "viewer")
    assert [d["source"] for d in c.get("/api/devices").json()["items"]] == ["tailscale"]
    assert [e["source"] for e in c.get("/api/events").json()["items"]] == ["tailscale"]
    assert c.get("/api/devices", params={"source": "demo_mock"}).json()["total"] == 1  # asked by name: still there
    assert api.mock_sources() == ("demo_mock",)
    assert live.counts(api.mock_sources())["devices"]["by_source"] == {"tailscale": 1}
    assert live.counts_since("2026-01-01T00:00:00Z", api.mock_sources())["by_severity"] == {"critical": 1}
