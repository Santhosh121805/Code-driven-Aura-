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
    assert login.status_code == 200 and 'id="signin"' in login.text


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
    from integration_platform.embed_configs import BLOCK
    for name in ("landing.html", "docs.html", "login.html", "site.js"):
        text = BLOCK.sub("", (STATIC / name).read_text(encoding="utf-8"))  # embedded YAML shows third-party API paths as text
        text = re.sub(r"<pre\b.*?</pre>", "", text, flags=re.S)  # docs code examples show vendor API paths, not our calls
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


def test_home_page_shows_the_real_configs():
    """The code tabs embed the real YAML at build time; re-run `python -m integration_platform.embed_configs` after a config change."""
    from integration_platform.embed_configs import config_text, embedded_files
    page = (STATIC / "landing.html").read_text(encoding="utf-8")
    files = embedded_files(page)
    assert set(files) == {"configs/integrations/github.yaml", "configs/integrations/okta.yaml", "configs/integrations/jira.yaml",
                          "configs/integrations/nvd.yaml", "configs/examples/cisa_kev.yaml"}
    for rel, text in files.items():
        assert text == config_text(rel), f"{rel} is out of date on the home page: run python -m integration_platform.embed_configs"
        assert "${" in text or "type: none" in text  # secrets only by name


def test_public_pages_do_not_mention_the_event_or_organiser():
    for name in ("landing.html", "docs.html", "login.html", "site.js", "site.css"):
        text = (STATIC / name).read_text(encoding="utf-8").lower()
        assert "mitigata" not in text and "cyberforge" not in text, name


def test_dashboard_screenshots_are_local_files():
    page = client().get("/").text
    for shot in ("overview", "integrations", "events"):
        assert (STATIC / "shots" / f"{shot}.png").stat().st_size > 10_000
    assert "/static/shots/overview.png" in page and "http" not in page.split('id="shotImg"')[1].split(">")[0]


def test_theme_is_set_before_first_paint_and_shared_with_the_app():
    """No flash: an inline <head> script picks the saved theme (else the system setting) before any stylesheet loads."""
    for name in ("landing.html", "docs.html", "login.html", "index.html"):
        html = (STATIC / name).read_text(encoding="utf-8")
        head = html.split("</head>")[0]
        script = head.index('localStorage.getItem("theme")')
        assert script < head.index('rel="stylesheet"'), name
        assert "prefers-color-scheme: light" in head and "try {" in head, name
    for name in ("landing.html", "docs.html", "login.html"):
        assert 'class="icon-btn theme-toggle"' in (STATIC / name).read_text(encoding="utf-8"), name
