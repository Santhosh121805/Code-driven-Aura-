"""Public home page, docs and sign-in: what is open, what redirects, and what must never leak."""
import re

import pytest
from fastapi.testclient import TestClient

from integration_platform import api, auth
from integration_platform.db import Database
from tests.conftest import ROOT, TEST_PASSWORD, signed_in

STATIC = ROOT / "integration_platform" / "static"
PUBLIC_API_CALLS = {"/api/auth/options", "/api/auth/login"}


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(api.state, "db", Database(tmp_path / "public.db"), raising=False)
    auth._failures.clear()


def client() -> TestClient:
    return TestClient(api.app, follow_redirects=False)


def test_public_pages_load_without_a_session():
    c = client()
    for path in ("/", "/docs", "/static/landing.html", "/static/docs.html", "/static/site.css", "/static/site.js", "/static/styles.css", "/health"):
        assert c.get(path).status_code == 200, path
    assert "Connect any security tool with config, not code" in c.get("/").text
    assert 'id="security"' in c.get("/docs").text
    login = c.get("/login")
    assert login.status_code == 302 and login.headers["location"] == "/#signin"


def test_app_redirects_home_without_a_session_and_loads_with_one():
    c = client()
    resp = c.get("/app")
    assert resp.status_code == 302 and resp.headers["location"] == "/#signin"
    signed_in(c, "viewer")
    page = c.get("/app")
    assert page.status_code == 200 and 'id="appView"' in page.text


def test_protected_apis_return_401_without_a_session():
    c = client()
    for path in ("/api/events", "/api/users", "/api/devices", "/api/integrations", "/api/stats", "/api/actions", "/api/audit",
                 "/api/meta", "/api/auth/me", "/api/integrations/github/repo"):
        assert c.get(path).status_code == 401, path
    assert c.post("/api/integrations/github/run").status_code == 401
    assert c.get("/openapi.json").status_code == 404  # no public API schema


def test_public_pages_call_only_public_endpoints_and_show_no_live_data():
    for name in ("landing.html", "docs.html", "site.js"):
        text = (STATIC / name).read_text(encoding="utf-8")
        calls = set(re.findall(r"/api/[a-z0-9_/{}-]+", text))
        assert calls <= PUBLIC_API_CALLS, (name, calls - PUBLIC_API_CALLS)


def test_role_comes_from_the_server_not_the_client():
    c = client()
    resp = c.post("/api/auth/login", json={"username": "analyst", "password": TEST_PASSWORD, "role": "admin"})
    assert resp.json() == {"user": "analyst", "role": "analyst"}  # the extra "role" field is ignored
    assert c.get("/api/auth/me").json()["role"] == "analyst"
    assert c.get("/api/audit").status_code == 403  # admin only
    c.cookies.clear()
    c.cookies.set(auth.COOKIE, auth.issue_session("analyst", "admin"))  # a forged role claim: signature ok, role mismatch
    assert c.get("/api/auth/me").status_code == 401


def test_cooldown_after_five_failures_then_a_fresh_start():
    now = 1_000_000.0
    for _ in range(auth.MAX_FAILURES):
        assert auth.cooldown_left("1.2.3.4", "Admin", now) == 0
        auth.note_failure("1.2.3.4", "admin", now)
    assert auth.cooldown_left("1.2.3.4", "admin ", now + 1) == 29  # username is case/space-insensitive
    assert auth.cooldown_left("5.6.7.8", "admin", now + 1) == 0     # other address: not affected
    assert auth.cooldown_left("1.2.3.4", "viewer", now + 1) == 0    # other username: not affected
    assert auth.cooldown_left("1.2.3.4", "admin", now + auth.COOLDOWN_SECONDS + 1) == 0
    assert auth.cooldown_left("1.2.3.4", "admin", now + auth.COOLDOWN_SECONDS + 2) == 0  # budget was reset


def test_one_address_cannot_cycle_through_usernames():
    now = 2_000_000.0
    for i in range(auth.MAX_FAILURES_PER_ADDRESS):
        auth.note_failure("9.9.9.9", f"user{i}", now)
    assert auth.cooldown_left("9.9.9.9", "someone-new", now + 1) > 0


def test_success_clears_the_failure_count():
    c = client()
    for _ in range(auth.MAX_FAILURES - 1):
        c.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert c.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD}).status_code == 200
    assert c.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401  # not 429


def test_demo_options_prefill_usernames_but_never_passwords(monkeypatch):
    c = client()
    monkeypatch.setenv("DEMO_MODE", "on")
    on = c.get("/api/auth/options").json()
    assert on == {"demo": True, "usernames": {"admin": "admin", "analyst": "analyst", "viewer": "viewer"}}
    monkeypatch.setenv("DEMO_MODE", "")
    assert c.get("/api/auth/options").json() == {"demo": False, "usernames": {}}


def test_no_passwords_or_hashes_in_any_page():
    monkeypatch_env = auth.load_users()
    hashes = [h for _, h in monkeypatch_env.values()]
    c = client()
    bodies = [c.get(p).text for p in ("/", "/docs", "/static/site.js", "/static/app.js", "/api/auth/options")]
    signed_in(c, "admin")
    bodies.append(c.get("/app").text)
    for body in bodies:
        assert TEST_PASSWORD not in body
        assert "scrypt$" not in body and not any(h in body for h in hashes)


def test_sign_out_clears_the_session():
    c = client()
    signed_in(c, "viewer")
    assert c.get("/app").status_code == 200
    c.post("/api/auth/logout")
    assert c.get("/app").status_code == 302
