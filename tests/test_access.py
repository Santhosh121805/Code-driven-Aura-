"""Sign-in, roles (viewer < analyst < admin), the audit trail, search filters and the GitHub repository card."""
import types

import httpx
import pytest
from fastapi.testclient import TestClient

from integration_platform import api, auth
from integration_platform.db import Database
from tests.conftest import TEST_PASSWORD, load, signed_in


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(tmp_path / "access.db")
    monkeypatch.setattr(api.state, "db", database, raising=False)
    auth._failures.clear()
    return database


def client(role: str | None = None) -> TestClient:
    c = TestClient(api.app)
    return signed_in(c, role) if role else c


def test_api_needs_a_session_but_the_page_and_health_do_not(db):
    c = client()
    assert c.get("/api/events").status_code == 401
    assert c.get("/api/auth/me").status_code == 401
    assert c.get("/").status_code == 200 and c.get("/health").status_code == 200


def test_sign_in_sets_an_httponly_cookie_and_me_returns_the_role(db):
    c = TestClient(api.app)
    resp = c.post("/api/auth/login", json={"username": "analyst", "password": TEST_PASSWORD})
    assert resp.json() == {"user": "analyst", "role": "analyst"}
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert c.get("/api/auth/me").json() == {"user": "analyst", "role": "analyst"}
    c.post("/api/auth/logout")
    assert c.get("/api/auth/me").status_code == 401


def test_wrong_password_is_rejected_audited_and_cooled_down(db):
    c = TestClient(api.app)
    for _ in range(auth.MAX_FAILURES):
        resp = c.post("/api/auth/login", json={"username": "admin", "password": "nope"})
        assert (resp.status_code, resp.json()["detail"]) == (401, "Invalid username or password")
    blocked = c.post("/api/auth/login", json={"username": "admin", "password": TEST_PASSWORD})  # even the right password
    assert blocked.status_code == 429 and 0 < int(blocked.headers["Retry-After"]) <= auth.COOLDOWN_SECONDS
    actions = [e["action"] for e in db.list_audit()]
    assert actions[0] == "Sign-in blocked (cooldown)" and actions[1:6] == ["Sign-in failed"] * 5
    assert c.post("/api/auth/login", json={"username": "viewer", "password": TEST_PASSWORD}).status_code == 200  # per username


def test_viewer_reads_but_cannot_change_anything(db):
    c = client("viewer")
    assert c.get("/api/events").status_code == 200
    assert c.post("/api/integrations/github/run").status_code == 403
    assert c.post("/api/integrations/github/disable").status_code == 403
    assert c.post("/api/ai/suggest-mapping", json={"sample": []}).status_code == 403
    assert c.get("/api/audit").status_code == 403 and c.get("/api/secrets").status_code == 403
    denied = db.list_audit()[0]
    assert (denied["user"], denied["role"], denied["outcome"]) == ("viewer", "viewer", "denied (admin only)")


def test_analyst_can_run_connectors_but_not_reconfigure_them(db):
    assert auth.required_role("POST", "/api/integrations/github/run") == "analyst"
    c = client("analyst")
    assert c.post("/api/integrations/github/disable").status_code == 403
    assert c.post("/api/demo/reset").status_code == 403
    assert c.post("/api/integrations", json={"yaml": "name: x"}).status_code == 403


def test_every_write_endpoint_is_admin_only_except_run():
    """Guard against a new endpoint being exposed by accident: only 'run' is open to analysts."""
    for route in api.app.routes:
        for method in getattr(route, "methods", None) or ():
            path = getattr(route, "path", "")
            if not path.startswith("/api/") or path in api.PUBLIC_API or method in ("GET", "HEAD"):
                continue
            expected = "analyst" if path == "/api/integrations/{name}/run" else "admin"
            assert auth.required_role(method, path.replace("{name}", "github")) == expected, (method, path)


def test_admin_sees_the_audit_log_of_actions(db):
    c = client("admin")
    c.post("/api/integrations/validate", json={"yaml": "name: x"})  # pure computation: not audited
    log = c.get("/api/audit").json()["items"]
    assert [(e["user"], e["action"], e["outcome"]) for e in log] == [("admin", "Signed in", "ok")]


def test_tampered_expired_or_stale_sessions_are_rejected(monkeypatch):
    token = auth.issue_session("admin", "admin")
    assert auth.read_session(token) == {"user": "admin", "role": "admin"}
    payload, sig = token.rsplit(".", 1)
    forged = auth._b64(b'{"u": "admin", "r": "admin", "exp": 9999999999}')
    assert auth.read_session(f"{forged}.{sig}") is None
    assert auth.read_session(token, now=10 ** 11) is None  # expired
    assert auth.read_session(auth.issue_session("admin", "viewer")) is None  # role no longer matches .env
    monkeypatch.setenv(auth.USERS_ENV, "")
    assert auth.read_session(token) is None  # user removed


def test_passwords_are_only_stored_as_scrypt_hashes(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRETS_KEY=x\n", encoding="utf-8")
    created = auth.ensure_default_users(str(env))
    text = env.read_text(encoding="utf-8")
    assert set(created) == {"admin", "analyst", "viewer"}
    assert all(pw not in text for pw in created.values()) and text.count("scrypt$") == 3
    assert auth.ensure_default_users(str(env)) == {}  # never overwrites existing users
    assert auth.verify_password("pw-1", auth.hash_password("pw-1")) and not auth.verify_password("pw-2", auth.hash_password("pw-1"))


def test_events_search_and_since_filters(db):
    from integration_platform.config import validate_integration  # noqa: F401  (schema import side effects)
    for i, (desc, ts) in enumerate([("Pillow heap overflow", "2026-10-31T10:00:00Z"), ("Login from 10.0.0.5", "2026-10-01T10:00:00Z"),
                                    ("100%_literal", "2026-10-31T11:00:00Z")]):
        db._exec("INSERT INTO events (source, stream, id, type, severity, timestamp, description, raw, fetched_at) "
                 "VALUES ('github', 's', ?, 't', 'high', ?, ?, '{}', ?)", (f"e{i}", ts, desc, ts))
    c = client("viewer")
    assert [e["id"] for e in c.get("/api/events", params={"q": "pillow"}).json()["items"]] == ["e0"]
    assert [e["id"] for e in c.get("/api/events", params={"q": "10.0.0"}).json()["items"]] == ["e1"]
    assert [e["id"] for e in c.get("/api/events", params={"q": "%_"}).json()["items"]] == ["e2"]  # wildcards are literal
    assert {e["id"] for e in c.get("/api/events", params={"since": "2026-10-30T00:00:00Z"}).json()["items"]} == {"e0", "e2"}
    assert db.counts_since("2026-10-30T00:00:00Z")["events"] == 2


def test_github_repository_card(db, monkeypatch):
    for k, v in {"github_token": "test-token-not-real", "GITHUB_OWNER": "octo", "GITHUB_REPO": "demo"}.items():
        monkeypatch.setenv(k, v)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"full_name": "octo/demo", "description": "Demo repo", "topics": ["security"],
                                         "language": "Python", "stargazers_count": 3, "private": False})
    monkeypatch.setattr(api.state, "registry", types.SimpleNamespace(integrations={"github": load("github")},
                                                                      transport=httpx.MockTransport(handler)), raising=False)
    api._repo_cache.clear()
    db._exec("INSERT INTO events (source, stream, id, severity, timestamp, raw, fetched_at) VALUES "
             "('github', 'dependabot_alerts', 'd1', 'critical', 't', '{}', 't')")
    c = client("viewer")
    card = c.get("/api/integrations/github/repo").json()
    assert (card["full_name"], card["description"], card["topics"], card["language"]) == ("octo/demo", "Demo repo", ["security"], "Python")
    assert card["dependabot"] == {"critical": 1}
    assert calls[0].headers["Authorization"] == "Bearer test-token-not-real"
    c.get("/api/integrations/github/repo")
    assert len(calls) == 1  # cached


def test_audit_names_what_was_saved_even_without_a_name_in_the_url(db, monkeypatch):
    """POST /api/integrations and /api/secrets carry no {name} in the URL; the audit entry must still say what was saved."""
    from tests.conftest import OKTA_CONFIG
    stored = {}
    monkeypatch.setattr(api.state, "registry", types.SimpleNamespace(integrations={}, upsert=lambda cfg: stored.update(cfg=cfg.name)), raising=False)
    monkeypatch.setattr(api.state, "vault", types.SimpleNamespace(set=lambda n, v: None, info=lambda n: {}), raising=False)
    monkeypatch.setattr(api, "import_secrets", lambda refs: None)
    c = client("admin")
    assert c.post("/api/integrations", json={"config": OKTA_CONFIG}).status_code == 201
    assert c.post("/api/secrets", json={"name": "MY_TOOL_TOKEN", "value": "s3cr3t-value-123"}).status_code == 201
    log = [(e["action"], e["target"]) for e in db.list_audit()]
    assert ("Created integration", "okta_wizard") in log and ("Stored secret", "MY_TOOL_TOKEN") in log
    assert not any("s3cr3t-value-123" in str(e) for e in db.list_audit())


def test_open_demo_signin_accepts_any_credentials_with_the_picked_role(db, monkeypatch):
    monkeypatch.setenv("DEMO_OPEN_SIGNIN", "on")
    c = TestClient(api.app)
    assert c.get("/api/auth/options").json()["open"] is True
    r = c.post("/api/auth/login", json={"username": "judge", "password": "anything", "role": "analyst"})
    assert r.json() == {"user": "judge", "role": "analyst"}
    assert c.post("/api/integrations/github/disable").status_code == 403  # roles still apply
    c2 = TestClient(api.app)
    assert c2.post("/api/auth/login", json={"username": "", "password": "", "role": "root"}).json() == {"user": "viewer", "role": "viewer"}
    assert db.list_audit()[0]["action"] == "Signed in (open demo sign-in)"


def test_open_demo_signin_is_off_by_default(db, monkeypatch):
    monkeypatch.delenv("DEMO_OPEN_SIGNIN", raising=False)
    c = TestClient(api.app)
    assert c.get("/api/auth/options").json()["open"] is False
    r = c.post("/api/auth/login", json={"username": "admin", "password": "random", "role": "admin"})
    assert r.status_code == 401  # real passwords required; the picked role is ignored
