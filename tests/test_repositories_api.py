"""Repositories page API (all roles), per-endpoint path check (admin), multi-endpoint sample and test through the API."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from integration_platform import api, auth, engine
from integration_platform.db import Database
from tests.conftest import signed_in


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(tmp_path / "repos.db")
    monkeypatch.setattr(api.state, "db", database, raising=False)
    auth._failures.clear()
    return database


def repo_row(i, **extra):
    row = {"entity": "repository", "source": "github", "stream": "repositories", "id": str(i), "full_name": f"octo/r{i}",
           "url": f"https://github.com/octo/r{i}", "description": None, "summary": None, "summary_source": None,
           "topics": json.dumps(["security"] if i == 1 else []), "primary_language": "Python" if i < 3 else "Go",
           "languages": json.dumps({"Python": {"bytes": 9, "percent": 90.0}, "Shell": {"bytes": 1, "percent": 10.0}}),
           "visibility": "public" if i % 2 else "private", "is_fork": "False", "is_archived": "False", "default_branch": "main",
           "stars": str(i), "forks": "0", "open_issues": "1", "created_at": None, "last_pushed_at": f"2026-10-0{i}T00:00:00Z",
           "dependabot_status": "enabled", "fetched_at": "2026-11-01T00:00:00Z", "raw": {}}
    row.update(extra)
    return row


def alert(n, repo, sev):
    return {"entity": "event", "source": "github", "stream": "dependabot_alerts", "id": f"{repo}#{n}", "type": "dependabot_alert",
            "severity": sev, "timestamp": "2026-10-30T00:00:00Z", "description": f"pkg: advisory {n}", "resource": repo,
            "fetched_at": "2026-11-01T00:00:00Z", "raw": {}}


@pytest.fixture
def seeded(db):
    for i in (1, 2, 3):
        db.store(repo_row(i))
    db.store(alert(1, "octo/r1", "critical"))
    db.store(alert(2, "octo/r1", "high"))
    db.store(alert(3, "octo/r3", "low"))
    return db


def test_viewer_sees_repositories_with_alert_counts_and_kpis(seeded):
    c = signed_in(TestClient(api.app), "viewer")
    d = c.get("/api/repositories").json()
    assert d["total"] == 3 and [r["full_name"] for r in d["items"]] == ["octo/r3", "octo/r2", "octo/r1"]  # last pushed first
    r1 = next(r for r in d["items"] if r["full_name"] == "octo/r1")
    assert (r1["alerts_critical"], r1["alerts_high"], r1["alerts_low"], r1["stars"], r1["is_fork"]) == (1, 1, 0, 1, False)
    assert r1["topics"] == ["security"] and r1["languages"]["Python"]["percent"] == 90.0 and "raw" not in r1
    assert d["kpis"]["repositories"] == 3 and d["kpis"]["with_critical"] == 1 and d["kpis"]["languages"] == 3  # Python, Shell, Go
    assert d["kpis"]["alerts"] == {"critical": 1, "high": 1, "medium": 0, "low": 1}
    assert d["facets"] == {"languages": ["Go", "Python"], "topics": ["security"], "visibility": ["private", "public"]}


@pytest.mark.parametrize("params,expected", [
    ({"q": "r2"}, ["octo/r2"]), ({"q": "security"}, ["octo/r1"]), ({"language": "Go"}, ["octo/r3"]),
    ({"topic": "security"}, ["octo/r1"]), ({"visibility": "private"}, ["octo/r2"]), ({"critical": "true"}, ["octo/r1"]),
])
def test_repository_filters(seeded, params, expected):
    c = signed_in(TestClient(api.app), "viewer")
    assert [r["full_name"] for r in c.get("/api/repositories", params=params).json()["items"]] == expected


def test_events_filter_by_resource(seeded):
    c = signed_in(TestClient(api.app), "viewer")
    assert {e["id"] for e in c.get("/api/events", params={"resource": "octo/r1"}).json()["items"]} == {"octo/r1#1", "octo/r1#2"}


def test_mapping_check_verifies_each_path_against_the_sample(db):
    c = signed_in(TestClient(api.app), "admin")
    sample = {"data": [{"id": 1, "name": "a", "owner": {"login": "x"}}, {"id": 2, "name": "b"}]}
    r = c.post("/api/mapping/check", json={"sample": sample, "records_path": "data",
                                           "mapping": {"id": "id", "full_name": "owner.login", "url": "nope", "summary": "parent().x", "bad": "a["}}).json()
    assert r["records"] == 2
    f = r["fields"]
    assert f["id"] == {"ok": True, "example": 1, "found_in": 2, "of": 2, "note": ""}
    assert f["full_name"]["ok"] and f["full_name"]["found_in"] == 1
    assert f["url"]["ok"] is False and f["summary"]["ok"] and "run time" in f["summary"]["note"]
    assert f["bad"] == {"ok": False, "error": "not a valid JMESPath expression"}
    assert not [a for a in db.list_audit() if "mapping" in a["action"]]  # a pure computation: not audited
    assert signed_in(TestClient(api.app), "viewer").post("/api/mapping/check", json={"sample": []}).status_code == 403


def two_endpoint_config():
    return {"name": "two_eps", "display_name": "Two endpoints", "base_url": "https://two.example.test", "auth": {"type": "none"},
            "streams": [
                {"name": "events", "entity": "event", "endpoint": "/events", "records_path": "results",
                 "mapping": {"id": "event_id", "timestamp": "time", "description": "message"}},
                {"name": "devices", "entity": "device", "endpoint": "/devices", "records_path": "results",
                 "mapping": {"id": "mac", "hostname": "hostname"}}]}


def two_endpoint_api(request):
    if request.url.path == "/events":
        return httpx.Response(200, json={"results": [{"event_id": "e1", "time": "2026-10-31T10:00:00Z", "message": "hello"}]})
    if request.url.path == "/devices":
        return httpx.Response(200, json={"results": [{"mac": "aa", "hostname": "h1"}, {"mac": "bb", "hostname": "h2"}]})
    return httpx.Response(404)


def test_sample_and_test_per_endpoint(db, monkeypatch):
    real = httpx.AsyncClient

    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(two_endpoint_api)
        return real(*a, **kw)
    monkeypatch.setattr(engine.httpx, "AsyncClient", fake_client)
    c = signed_in(TestClient(api.app), "admin")
    cfg = two_endpoint_config()
    cfg["streams"][1]["mapping"] = {}  # mapping not decided yet: the sample still works
    s = c.post("/api/integrations/sample", json={"config": cfg, "stream": 1}).json()
    assert s["ok"] and s["record_count"] == 2 and s["sample"]["results"][0]["hostname"] == "h1"
    t = c.post("/api/integrations/test", json={"config": two_endpoint_config()}).json()
    assert t["ok"] and [(x["name"], x["status"], len(x["normalised"])) for x in t["streams"]] == [("events", "ok", 1), ("devices", "ok", 2)]
    assert t["streams"][1]["normalised"][0]["hostname"] == "h1" and t["streams"][1]["raw"][0]["mac"] == "aa"


def test_integration_summary_lists_endpoints_with_last_status(db, monkeypatch):
    import types
    from integration_platform.config import validate_integration
    cfg = validate_integration(two_endpoint_config())
    run = db.start_run("two_eps")
    db.finish_run(run, "partial", 1, 1, 1, 0, "devices: HTTP 500", 0, {"streams": [
        {"name": "events", "status": "ok", "fetched": 1, "new": 1, "updated": 0, "quarantined": 0},
        {"name": "devices", "status": "error", "error": "HTTP 500 from /devices", "fetched": 0, "new": 0, "updated": 0, "quarantined": 0}]})
    monkeypatch.setattr(api.state, "registry", types.SimpleNamespace(integrations={"two_eps": cfg}, next_run=lambda n: None), raising=False)
    monkeypatch.setattr(api.state, "vault", None, raising=False)
    d = signed_in(TestClient(api.app), "viewer").get("/api/integrations/two_eps").json()
    eps = {s["name"]: s for s in d["streams"]}
    assert eps["events"]["last_status"] == "ok" and eps["events"]["fetched"] == 1
    assert eps["devices"]["last_status"] == "error" and "HTTP 500" in eps["devices"]["error"]
