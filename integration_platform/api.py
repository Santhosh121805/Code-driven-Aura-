"""FastAPI app: REST API + static single-page UI. Run: uvicorn integration_platform.api:app"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import jmespath
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from integration_platform.config import (
    ENTITIES, ENTITY_FIELDS, MUST_MAP, ROOT, join_url, ActionConfig, ConfigError, IntegrationConfig, MissingSecretError, load_action_files,
    load_integration_files, missing_settings, parse_yaml, resolve_env, risky_scopes, to_yaml, validate_integration,
)

ENV_FILE = os.environ.get("INTEGRATION_HUB_ENV_FILE", str(ROOT / ".env"))  # tests set this to "" to stay hermetic
if ENV_FILE:
    load_dotenv(ENV_FILE, override=False)  # before anything reads secrets

from integration_platform import ai_mapper, auth, catalog, demo, demo_mock, logmask  # noqa: E402
from integration_platform.actions import ActionRunner  # noqa: E402
from integration_platform.alerts import FailureAlerter  # noqa: E402
from integration_platform.db import TABLES, Database  # noqa: E402
from integration_platform.engine import GUARD_SOURCE, EngineError, dry_run_integration, extract_records, fetch_sample  # noqa: E402
from integration_platform.normaliser import search as jmes_search  # noqa: E402
from integration_platform.scheduler import SEEDED_INTEGRATIONS, Registry  # noqa: E402
from integration_platform.vault import Vault, connector_secret_status, ensure_secrets_key, parse_age_overrides, secret_refs  # noqa: E402

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logging.getLogger("httpx").setLevel(logging.WARNING)
if ENV_FILE:  # not under pytest: also keep a log file (git-ignored, masked like the console)
    from logging.handlers import RotatingFileHandler
    (ROOT / "logs").mkdir(exist_ok=True)
    _file = RotatingFileHandler(ROOT / "logs" / "platform.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    _file.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger().addHandler(_file)
logmask.install()  # mask token-like strings in every log line (console AND file)
log = logging.getLogger("api")
STATIC = Path(__file__).parent / "static"
SAMPLE_RECORDS = 20  # the wizard only needs a sample; huge feeds (KEV: 1,700+ records) are trimmed


class State:
    db: Database
    vault: Vault
    actions: ActionRunner
    registry: Registry


state = State()


def import_secrets(refs: list[str]) -> None:
    """Encrypt referenced secrets from the environment into the vault (first use only)."""
    imported = state.vault.import_from_env(refs, parse_age_overrides(os.environ.get("SECRET_AGE_OVERRIDES")))
    if imported:
        log.info("encrypted %d secret(s) into the vault: %s", len(imported), ", ".join(imported))


LEGACY_SECRET_NAMES = ("JIRA_USER", "JIRA_TOKEN", "OKTA_CLIENT_ID", "OKTA_CLIENT_SECRET", "ACME_FW_API_KEY", "AWS_CLOUDTRAIL_TOKEN")


def bootstrap_secrets() -> None:
    for name in LEGACY_SECRET_NAMES:  # obsolete mock-era secret names: drop orphaned encrypted copies
        state.db.delete_secret(name)
    configs = list(load_integration_files()[0].values()) + list(load_action_files()[0].values())
    import_secrets(sorted({ref for cfg in configs for ref in secret_refs(cfg)}))


@asynccontextmanager
async def lifespan(_: FastAPI):
    state.db = Database()
    state.vault = Vault(state.db, ensure_secrets_key(ROOT / ".env"))
    state.vault.activate()
    bootstrap_secrets()
    state.actions = ActionRunner(state.db)
    state.registry = Registry(state.db, state.actions, state.vault, FailureAlerter(state.db, state.actions))
    state.registry.start()
    log.info("loaded integrations: %s", ", ".join(state.registry.integrations) or "none")
    yield
    state.registry.shutdown()


# docs_url/redoc_url off: /docs is our own static documentation (Swagger UI would also pull from a CDN).
app = FastAPI(title="Config-Driven Integration Platform", version="2.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.include_router(demo_mock.router)  # /mock/events: the Demo source (Mock), read only by demo controls


@app.exception_handler(ConfigError)
async def _config_error(_, exc: ConfigError) -> JSONResponse:
    return JSONResponse({"ok": False, "stage": "validation", "errors": exc.errors}, status_code=422)


# ------------------------------------------------------------------ sign-in, roles, audit
PUBLIC_API = {"/api/auth/login", "/api/auth/logout", "/api/auth/options"}
AUDIT_SKIP = {"/api/integrations/validate", "/api/convert", "/api/mapping/check"}  # pure computations: no state change, no outbound call
AUDIT_LABELS = {
    ("POST", "/api/integrations"): "Created integration", ("PUT", "/api/integrations/{name}"): "Updated integration",
    ("DELETE", "/api/integrations/{name}"): "Deleted integration", ("POST", "/api/integrations/{name}/enable"): "Enabled integration",
    ("POST", "/api/integrations/{name}/disable"): "Disabled integration", ("POST", "/api/integrations/{name}/resume"): "Resumed integration",
    ("POST", "/api/integrations/{name}/revoke"): "Revoked secrets", ("POST", "/api/integrations/{name}/run"): "Ran integration",
    ("POST", "/api/integrations/test"): "Tested connection", ("POST", "/api/integrations/sample"): "Fetched sample",
    ("POST", "/api/secrets"): "Stored secret", ("POST", "/api/ai/suggest-mapping"): "Suggested mapping",
    ("POST", "/api/demo/network-off"): "Demo: network off", ("POST", "/api/demo/wrong-key"): "Demo: wrong key",
    ("POST", "/api/demo/repeated-failure"): "Demo: repeated failure", ("POST", "/api/demo/reset"): "Reset demo",
    ("POST", "/api/alerts/test"): "Sent test alert",
    ("POST", "/api/demo/firewall-429"): "Demo: rate limit", ("POST", "/api/demo/retry-after"): "Demo: Retry-After",
    ("POST", "/api/demo/malformed"): "Demo: malformed record", ("POST", "/api/demo/bulk-export"): "Demo: bulk export",
}


def _audit(user: str, role: str | None, action: str, target: str | None, outcome: str) -> None:
    try:
        state.db.add_audit(user, role, action, target, outcome)
    except Exception:  # auditing must never break the request (e.g. DB not ready in a unit test)
        log.exception("could not write audit entry")


@app.middleware("http")
async def always_fresh_ui(request: Request, call_next):
    """Pages and /static files: the browser must revalidate on every load (a 304 when unchanged), so it never mixes a
    new page with an old cached app.js / site.css after an update."""
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/") or path in ("/", "/app", "/docs", "/login"):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.middleware("http")
async def require_sign_in(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path in PUBLIC_API:
        return await call_next(request)
    session = auth.read_session(request.cookies.get(auth.COOKIE))
    if session is None:
        return JSONResponse({"detail": "Not signed in"}, status_code=401)
    needed = auth.required_role(request.method, path)
    if not auth.allowed(session["role"], needed):
        _audit(session["user"], session["role"], f"{request.method} {path}", None, f"denied ({needed} only)")
        return JSONResponse({"detail": f"{needed.capitalize()} role required"}, status_code=403)
    request.state.session = session
    response = await call_next(request)
    if request.method not in ("GET", "HEAD") and path not in AUDIT_SKIP:
        route = request.scope.get("route")
        template = getattr(route, "path", path)
        label = getattr(request.state, "audit_action", None) or AUDIT_LABELS.get((request.method, template), f"{request.method} {template}")
        # {name} from the URL (filled in by the router during call_next), else what the endpoint reported
        target = request.scope.get("path_params", {}).get("name") or getattr(request.state, "audit_target", None)
        _audit(session["user"], session["role"], label, target, "ok" if response.status_code < 400 else f"failed ({response.status_code})")
    return response


class LoginIn(BaseModel):
    username: str = ""
    password: str = ""
    role: str | None = None  # only used with DEMO_OPEN_SIGNIN=on (the picked tab); otherwise ignored


INVALID_LOGIN = "Invalid username or password"  # one message: never say which part was wrong


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response) -> dict[str, Any]:
    """The role comes from the account on the server; the picked tab is ignored. Exception: DEMO_OPEN_SIGNIN=on accepts
    any credentials and uses the picked role (live demos), still audited."""
    if auth.open_signin():
        role = body.role if body.role in auth.ROLES else "viewer"
        user = (body.username.strip() or role)[:64]
        response.set_cookie(auth.COOKIE, auth.issue_session(user, role), max_age=auth.SESSION_SECONDS,
                            httponly=True, samesite="lax", secure=request.url.scheme == "https", path="/")
        _audit(user, role, "Signed in (open demo sign-in)", None, "ok")
        return {"user": user, "role": role}
    client = request.client.host if request.client else "unknown"
    wait = auth.cooldown_left(client, body.username)
    if wait:
        _audit(body.username[:64] or "?", None, "Sign-in blocked (cooldown)", None, "denied")
        raise HTTPException(429, f"Too many attempts. Try again in {wait} s.", headers={"Retry-After": str(wait)})
    role = auth.authenticate(body.username, body.password)
    if role is None:
        auth.note_failure(client, body.username)
        _audit(body.username[:64] or "?", None, "Sign-in failed", None, "denied")
        raise HTTPException(401, INVALID_LOGIN)
    auth.clear_failures(client, body.username)
    response.set_cookie(auth.COOKIE, auth.issue_session(body.username, role), max_age=auth.SESSION_SECONDS,
                        httponly=True, samesite="lax", secure=request.url.scheme == "https", path="/")
    _audit(body.username, role, "Signed in", None, "ok")
    return {"user": body.username, "role": role}


@app.get("/api/auth/options")
def login_options() -> dict[str, Any]:
    """Public: what the sign-in card may show. Demo mode pre-fills usernames per role; passwords are never exposed."""
    demo = auth.demo_mode()
    return {"demo": demo, "usernames": auth.demo_usernames() if demo else {}, "open": auth.open_signin()}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict[str, Any]:
    session = auth.read_session(request.cookies.get(auth.COOKIE))
    if session:
        _audit(session["user"], session["role"], "Signed out", None, "ok")
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request) -> dict[str, Any]:
    return request.state.session


@app.get("/api/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    return {"items": state.db.list_audit(limit)}


# ------------------------------------------------------------------ helpers
class ConfigIn(BaseModel):
    """Accepts either YAML text or a JSON object (the wizard sends `config`, the YAML editor sends `yaml`)."""
    yaml: str | None = None
    config: dict[str, Any] | None = None
    stream: int = 0  # which stream the wizard is working on (sample endpoint)

    def data(self) -> dict[str, Any]:
        if self.config is not None:
            return copy.deepcopy(self.config)
        if self.yaml is not None:
            return parse_yaml(self.yaml)
        raise ConfigError(["Send either 'yaml' (text) or 'config' (object)"])

    def to_config(self) -> IntegrationConfig:
        return validate_integration(self.data())


def _dump(cfg: IntegrationConfig | ActionConfig) -> dict[str, Any]:
    # Configs only ever contain ${VAR} references, never secret values, so this is safe to return.
    return cfg.model_dump(mode="json", exclude_none=True)


RECOVERY_WINDOW = timedelta(minutes=5)


def _recent_recovery(finished: list[dict]) -> dict | None:
    """Newest successful run that needed retries, if it finished within RECOVERY_WINDOW."""
    cutoff = (datetime.now(timezone.utc) - RECOVERY_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    return next((r for r in finished if r["status"] in ("success", "suspicious") and r["retries"] and r["finished_at"] >= cutoff), None)


def _health(cfg: IntegrationConfig) -> dict[str, Any]:
    runs = state.db.recent_runs(cfg.name, 10)
    finished = [r for r in runs if r["status"] != "running"]
    last = finished[0] if finished else None
    last_error_run = next((r for r in finished if r["status"] in ("error", "partial")), None)
    connector_state = state.db.get_state(cfg.name)
    kind = connector_state["state"] if connector_state else None
    missing = missing_settings(cfg)
    if kind == "suspicious":
        d = connector_state["detail"]
        status, colour, summary = "suspicious", "red", f"SUSPICIOUS: auto-paused ({d['records']} records vs baseline {d['baseline']:g})"
    elif kind == "revoked":
        status, colour, summary = "revoked", "grey", "Revoked: credentials wiped"
    elif not cfg.enabled:
        status, colour, summary = "disabled", "grey", "Disabled"
    elif missing:
        status, colour, summary = "not_configured", "grey", "Not configured"
    elif last is None:
        status, colour, summary = "pending", "amber", "Waiting for first run"
    elif last["status"] == "error":
        auth = "Authentication failed" in (last["error"] or "")
        status, colour, summary = ("auth_failed", "red", "Authentication failed") if auth else ("error", "red", "Last run failed")
    elif last["status"] == "partial":
        status, colour, summary = "partial", "amber", "Partial: a stream failed"
    elif recovered := _recent_recovery(finished):
        # Keep showing a recovery for a few minutes so it does not vanish at the next scheduled run.
        status, colour, summary = "degraded", "amber", f"Recovered after {recovered['retries']} retr{'y' if recovered['retries'] == 1 else 'ies'}"
    else:
        status, colour, summary = "healthy", "green", "Healthy"
    secrets = connector_secret_status(cfg, getattr(state, "vault", None))
    warnings = [{"kind": "rotate", "text": f"Rotate secret: {s['name']} is {s['age_days']} days old (policy {s['max_age_days']})"}
                for s in secrets if s["rotate"]]
    if risky := risky_scopes(cfg.scopes):
        warnings.append({"kind": "scope", "text": f"Write/admin scope: {', '.join(risky)}"})
    failures = state.db.get_failure_state(cfg.name)
    return {
        "status": status, "colour": colour, "summary": summary, "missing": missing,
        "state": connector_state, "warnings": warnings, "secrets": secrets,
        "running": bool(runs and runs[0]["status"] == "running"),
        "last_run": last,
        "last_error": {"error": last_error_run["error"], "at": last_error_run["finished_at"]} if last_error_run else None,
        "next_run": state.registry.next_run(cfg.name),
        "totals": state.db.run_totals(cfg.name),
        "counts": state.db.source_counts(cfg.name),
        "quarantined_total": state.db.quarantine_count(cfg.name),
        "failure_streak": failures["streak"], "failure_alerted": bool(failures["alerted_at"]),
    }


def _stream_status(cfg: IntegrationConfig) -> list[dict[str, Any]]:
    """Each endpoint with its outcome in the latest run that reached it: records, last status, last error, skipped items."""
    last: dict[str, dict[str, Any]] = {}
    for run in state.db.recent_runs(cfg.name, 10):
        for s in (run.get("detail") or {}).get("streams", []):
            if s["name"] not in last and s.get("status") not in (None, "not run"):
                last[s["name"]] = {**s, "at": run["finished_at"]}
    out = []
    for s in cfg.streams:
        r = last.get(s.name, {})
        out.append({"name": s.name, "entity": s.entity, "endpoint": s.endpoint, "pagination": s.pagination.type,
                    "for_each": s.for_each.stream if s.for_each else None, "merge_into_parent": s.merge_into_parent,
                    "last_status": r.get("status"), "last_at": r.get("at"), "fetched": r.get("fetched"), "new": r.get("new"),
                    "updated": r.get("updated"), "quarantined": r.get("quarantined"), "skipped": r.get("skipped"),
                    "skipped_reasons": r.get("skipped_reasons"), "items": r.get("items"), "error": r.get("error"),
                    "note": r.get("note")})
    return out


def _summary(cfg: IntegrationConfig) -> dict[str, Any]:
    return {
        "name": cfg.name, "display_name": cfg.display_name, "enabled": cfg.enabled, "base_url": cfg.base_url,
        "auth_type": cfg.auth.type, "schedule_seconds": cfg.schedule_seconds,
        "streams": _stream_status(cfg),
        "seeded": cfg.name in SEEDED_INTEGRATIONS, "scopes": cfg.scopes, "risky_scopes": risky_scopes(cfg.scopes),
        "health": _health(cfg),
    }


def _get(name: str) -> IntegrationConfig:
    cfg = state.registry.integrations.get(name)
    if cfg is None:
        raise HTTPException(404, f"Integration '{name}' not found")
    return cfg


# ------------------------------------------------------------------ meta
NO_CACHE = {"Cache-Control": "no-cache"}


@app.get("/", include_in_schema=False)
def landing() -> FileResponse:
    """Public home page with the sign-in card. Static: no live data, no protected API calls."""
    return FileResponse(STATIC / "landing.html", headers=NO_CACHE)


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    """Full-page sign-in (the home page opens the same card as a modal)."""
    return FileResponse(STATIC / "login.html", headers=NO_CACHE)


@app.get("/docs", include_in_schema=False)
def docs_page() -> FileResponse:
    return FileResponse(STATIC / "docs.html", headers=NO_CACHE)


@app.get("/app", include_in_schema=False)
def app_page(request: Request) -> Response:
    """The dashboard needs a session: otherwise back to the home page with the sign-in card open."""
    if auth.read_session(request.cookies.get(auth.COOKIE)) is None:
        return RedirectResponse("/#signin", status_code=302)
    return FileResponse(STATIC / "index.html", headers=NO_CACHE)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


_repo_cache: dict[str, Any] = {}
REPO_CACHE_SECONDS = 300


@app.get("/api/integrations/github/repo")
async def github_repo() -> dict[str, Any]:
    """Repository card for the GitHub integration: name, description, topics, language (GitHub API, read-only,
    cached 5 min) + Dependabot alert counts by severity from the store."""
    cfg = state.registry.integrations.get("github")
    if cfg is None:
        raise HTTPException(404, "No GitHub integration")
    counts = state.db.severity_counts("github", "dependabot_alerts")
    try:
        owner, repo = resolve_env("${GITHUB_OWNER}"), resolve_env("${GITHUB_REPO}")
        token = resolve_env(cfg.auth.token) if cfg.auth.type == "bearer" else None
    except MissingSecretError as exc:
        return {"configured": False, "error": str(exc), "dependabot": counts}
    key = f"{owner}/{repo}"
    cached = _repo_cache.get(key)
    if cached and cached["at"] > datetime.now(timezone.utc) - timedelta(seconds=REPO_CACHE_SECONDS):
        return {**cached["data"], "dependabot": counts}
    headers = {**cfg.headers, **({"Authorization": f"Bearer {token}"} if token else {})}
    try:
        async with httpx.AsyncClient(timeout=10, transport=state.registry.transport) as client:
            resp = await client.get(f"{cfg.base_url.rstrip('/')}/repos/{owner}/{repo}", headers=headers)
    except httpx.HTTPError as exc:
        return {"configured": True, "error": f"GitHub unreachable: {type(exc).__name__}", "full_name": key, "dependabot": counts}
    if resp.status_code != 200:
        return {"configured": True, "error": f"GitHub returned HTTP {resp.status_code}", "full_name": key, "dependabot": counts}
    d = resp.json()
    data = {"configured": True, "full_name": d.get("full_name") or key, "description": d.get("description"),
            "topics": d.get("topics") or [], "language": d.get("language"), "stars": d.get("stargazers_count", 0),
            "private": d.get("private"), "html_url": d.get("html_url"), "default_branch": d.get("default_branch"),
            "pushed_at": d.get("pushed_at")}
    _repo_cache[key] = {"at": datetime.now(timezone.utc), "data": data}
    return {**data, "dependabot": counts}


@app.get("/api/catalog")
def integration_catalog() -> dict[str, Any]:
    """Tools customers use, with research notes, a status per tool and the capability gap table. Every role may read it;
    'Use template' only pre-fills the wizard, which is admin only."""
    return catalog.catalog_view(set(state.registry.integrations))


@app.get("/api/schema")
def schema() -> dict[str, Any]:
    """JSON Schema of the integration config (generated from the pydantic models)."""
    return IntegrationConfig.model_json_schema()


@app.get("/api/schema/action")
def action_schema() -> dict[str, Any]:
    return ActionConfig.model_json_schema()


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    jira, board = None, None
    for action in state.actions.actions.values():
        if "jira" in action.name:
            try:
                jira = resolve_env(action.request.base_url).rstrip("/")  # e.g. https://yourteam.atlassian.net
            except MissingSecretError:
                continue
            project = re.search(r'"project":\s*\{"key":\s*"([A-Z][A-Z0-9_]*)"', action.body_template)
            board = f"{jira}/browse/{project.group(1)}" if project else jira
    return {"llm_provider": ai_mapper.llm_provider(), "jira_base_url": jira, "jira_board_url": board, "seeded": list(SEEDED_INTEGRATIONS),
            "entity_fields": ENTITY_FIELDS, "config_load_errors": {**state.registry.load_errors, **state.actions.load_errors}}


@app.post("/api/convert")
def convert(body: ConfigIn) -> dict[str, Any]:
    """YAML <-> JSON for the wizard's live preview. Parses only; full validation happens in /validate."""
    if body.yaml is not None:
        return {"config": parse_yaml(body.yaml)}
    import yaml as pyyaml
    return {"yaml": pyyaml.safe_dump(body.config or {}, sort_keys=False, allow_unicode=True)}


@app.post("/api/integrations/validate")
def validate(body: ConfigIn) -> dict[str, Any]:
    cfg = body.to_config()
    return {"ok": True, "config": _dump(cfg), "yaml": to_yaml(cfg), "missing": missing_settings(cfg)}


# ------------------------------------------------------------------ integrations
@app.get("/api/integrations")
def list_integrations() -> dict[str, Any]:
    return {"items": [_summary(c) for c in state.registry.integrations.values()], "load_errors": state.registry.load_errors,
            "notifications": state.db.list_notifications(10)}


@app.get("/api/integrations/{name}")
def get_integration(name: str) -> dict[str, Any]:
    cfg = _get(name)
    out = {**_summary(cfg), "config": _dump(cfg), "yaml": to_yaml(cfg), "recent_runs": state.db.recent_runs(name, 15)}
    st = out["health"]["state"]
    if st and st["state"] == "suspicious" and st["detail"].get("event_id"):
        out["guard_event"] = state.db.get_event(GUARD_SOURCE, st["detail"]["event_id"])
    return out


@app.post("/api/integrations", status_code=201)
def create_integration(body: ConfigIn, request: Request, overwrite: bool = False) -> dict[str, Any]:
    cfg = body.to_config()
    request.state.audit_target = cfg.name  # no {name} in this URL: tell the audit log what was saved
    if cfg.name in state.registry.integrations and overwrite:
        request.state.audit_action = "Replaced integration"
    if cfg.name in state.registry.integrations and not overwrite:
        raise ConfigError([f"An integration named '{cfg.name}' already exists. Choose another name, or update it instead."])
    import_secrets(secret_refs(cfg))
    state.registry.upsert(cfg)
    log.info("integration %s saved and scheduled", cfg.name)
    return {"ok": True, "name": cfg.name, "message": f"{cfg.display_name} is live; first run starts now."}


@app.put("/api/integrations/{name}")
def update_integration(name: str, body: ConfigIn) -> dict[str, Any]:
    _get(name)
    cfg = body.to_config()
    if cfg.name != name:
        raise ConfigError([f"name cannot change on update (expected '{name}')"])
    import_secrets(secret_refs(cfg))
    state.registry.upsert(cfg)
    return {"ok": True, "name": name}


@app.delete("/api/integrations/{name}")
def delete_integration(name: str) -> dict[str, Any]:
    _get(name)
    state.registry.remove(name)
    return {"ok": True}


@app.get("/api/integrations/{name}/quarantine")
def quarantine(name: str, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    """Records that failed validation (missing fields, wrong types, bad times), newest first."""
    _get(name)
    return {"items": state.db.list_quarantine(name, limit), "total": state.db.quarantine_count(name)}


@app.post("/api/integrations/{name}/enable")
def enable(name: str) -> dict[str, Any]:
    _get(name)
    return _summary(state.registry.set_enabled(name, True))


@app.post("/api/integrations/{name}/disable")
def disable(name: str) -> dict[str, Any]:
    _get(name)
    return _summary(state.registry.set_enabled(name, False))


@app.post("/api/integrations/{name}/resume")
def resume(name: str) -> dict[str, Any]:
    """After review: clear SUSPICIOUS/REVOKED state and re-enable."""
    _get(name)
    return _summary(state.registry.resume(name))


@app.post("/api/integrations/{name}/revoke")
def revoke(name: str) -> dict[str, Any]:
    """Disable the connector and wipe its stored secrets from the vault."""
    _get(name)
    wiped = state.registry.revoke(name)
    return {"ok": True, "wiped_secrets": wiped, **_summary(_get(name))}


@app.post("/api/integrations/{name}/run")
async def run_now(name: str) -> dict[str, Any]:
    _get(name)
    return await state.registry.run_now(name, wait=True)


@app.post("/api/integrations/test")
async def test_config(body: ConfigIn) -> dict[str, Any]:
    """Test connection (B-3): run every stream once WITHOUT saving; first 5 raw + normalised records, or a clear error."""
    cfg = body.to_config()
    if missing := missing_settings(cfg):
        return {"ok": False, "stage": "config", "errors": [f"Not configured: set {', '.join(missing)} in .env (or store them in the vault)"]}
    try:
        return await dry_run_integration(cfg)
    except EngineError as exc:
        return {"ok": False, "stage": "fetch", "errors": [logmask.mask_text(str(exc))]}
    except Exception as exc:  # never 500 on a bad tool response
        log.exception("test failed")
        return {"ok": False, "stage": "fetch", "errors": [logmask.mask_text(f"{type(exc).__name__}: {exc}")]}


def _trim_sample(sample: Any) -> tuple[Any, int]:
    """Keep the response shape but at most SAMPLE_RECORDS records (returns trimmed sample, original record count)."""
    path, records = ai_mapper.detect_records_path(sample)
    count = len(records)
    if count <= SAMPLE_RECORDS:
        return sample, count
    if path is None:
        return sample[:SAMPLE_RECORDS], count
    trimmed = copy.deepcopy({k: v for k, v in sample.items()}) if isinstance(sample, dict) else sample
    return ai_mapper._truncate_at(trimmed, path, SAMPLE_RECORDS), count


@app.post("/api/integrations/sample")
async def sample(body: ConfigIn) -> dict[str, Any]:
    """Fetch the raw first page of one stream (mapping not required yet) for the AI mapping assistant."""
    data = body.data()
    for s in data.get("streams") or []:
        # Placeholders: the mapping is decided after seeing the sample (of this or any other endpoint).
        s["mapping"] = {f: "@" for f in ["id", *MUST_MAP.get(s.get("entity", "event"), [])]} | (s.get("mapping") or {})
    cfg = validate_integration(data)
    if missing := missing_settings(cfg):
        return {"ok": False, "stage": "config", "errors": [f"Not configured: set {', '.join(missing)} in .env"]}
    try:
        raw, link_next = await fetch_sample(cfg, min(body.stream, len(cfg.streams) - 1))
    except EngineError as exc:
        return {"ok": False, "stage": "fetch", "errors": [logmask.mask_text(str(exc))]}
    trimmed, count = _trim_sample(raw)
    return {"ok": True, "sample": trimmed, "link_next": link_next, "record_count": count,
            "trimmed": count > SAMPLE_RECORDS}


# ------------------------------------------------------------------ secrets (values are write-only)
class SecretIn(BaseModel):
    name: str
    value: str


@app.get("/api/secrets")
def list_secrets() -> dict[str, Any]:
    return {"items": [state.vault.info(r["name"]) for r in state.db.list_secrets()]}


@app.post("/api/secrets", status_code=201)
def store_secret(body: SecretIn, request: Request) -> dict[str, Any]:
    """Store (or rotate) a secret encrypted at rest. The value is never returned; configs reference ${NAME}."""
    request.state.audit_target = body.name  # the name only, never the value
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", body.name) or not body.value:
        raise HTTPException(422, "name must look like MY_TOOL_TOKEN and value must not be empty")
    state.vault.set(body.name, body.value)
    logmask.remember(body.value)
    return {"ok": True, "reference": f"${{{body.name}}}", **state.vault.info(body.name)}


# ------------------------------------------------------------------ common-schema data (one place, FR-11)
MOCK_LABEL = re.compile(r"\bmock\b", re.I)


def mock_sources() -> tuple[str, ...]:
    """Integrations labelled "(Mock)" (every mock must say so). The live data views leave them out; the demo controls
    and the Integrations page still show them. Asking for one source by name still returns its records.
    Platform alerts (source "plugsec_guard", e.g. token abuse on a mock connector) are not tool data: always shown."""
    registry = getattr(state, "registry", None)  # unit tests may run without one
    integrations = getattr(registry, "integrations", {}) or {}
    return tuple(sorted(name for name, cfg in integrations.items() if MOCK_LABEL.search(cfg.display_name)))


def _records(entity: str, source: str | None, severity: str | None, type_: str | None, limit: int, offset: int,
             q: str | None = None, since: str | None = None, resource: str | None = None) -> dict[str, Any]:
    items, total = state.db.list_records(entity, source or None, severity or None, type_ or None, limit, offset,
                                         q=(q or "").strip() or None, since=since or None, resource=resource or None,
                                         exclude_sources=mock_sources())
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/api/events")
def list_events(source: str | None = None, severity: str | None = None, type: str | None = None,  # noqa: A002
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                q: str | None = Query(None, max_length=200), since: str | None = None, resource: str | None = None) -> dict[str, Any]:
    """`q` searches id/type/description/host/IPs/user/ticket; `since` (ISO 8601 UTC) keeps events at or after it;
    `resource` = events of one resource (e.g. a repository's Dependabot alerts)."""
    return _records("event", source, severity, type, limit, offset, q, since, resource)


def _repository_view(r: dict[str, Any], alerts: dict[str, dict[str, int]]) -> dict[str, Any]:
    counts = alerts.get(r["full_name"], {})
    for sev in ("critical", "high", "medium", "low"):
        r[f"alerts_{sev}"] = counts.get(sev, 0)
    for key in ("stars", "forks", "open_issues"):
        r[key] = int(r[key]) if str(r.get(key) or "").isdigit() else 0
    for key in ("is_fork", "is_archived"):
        r[key] = r.get(key) == "True"
    r["topics"] = r.get("topics") or []
    r.pop("raw", None)
    return r


@app.get("/api/repositories")
def list_repositories(q: str | None = Query(None, max_length=200), language: str | None = None, topic: str | None = None,
                      visibility: str | None = None, critical: bool = False, source: str | None = None) -> dict[str, Any]:
    """Repositories (every source) with Dependabot alert counts per severity, KPIs and filter options."""
    alerts = state.db.resource_severity_counts()
    every = [_repository_view(r, alerts) for r in state.db.list_records("repository", source or None, limit=5000, exclude_sources=mock_sources())[0]]
    items = every
    needle = (q or "").strip().lower()
    if needle:
        items = [r for r in items if needle in " ".join(str(r.get(k) or "") for k in ("full_name", "description", "summary")).lower()
                 or any(needle in t.lower() for t in r["topics"])]
    if language:
        items = [r for r in items if r.get("primary_language") == language]
    if topic:
        items = [r for r in items if topic in r["topics"]]
    if visibility:
        items = [r for r in items if r.get("visibility") == visibility]
    if critical:
        items = [r for r in items if r["alerts_critical"]]
    languages = sorted({r["primary_language"] for r in every if r.get("primary_language")})
    kpis = {"repositories": len(every),
            "with_critical": sum(1 for r in every if r["alerts_critical"]),
            "languages": len({lang for r in every for lang in (r.get("languages") or {})} | set(languages)),
            "last_updated": max((r["fetched_at"] for r in every), default=None),
            "alerts": {sev: sum(r[f"alerts_{sev}"] for r in every) for sev in ("critical", "high", "medium", "low")}}
    return {"items": items, "total": len(every), "shown": len(items), "kpis": kpis,
            "facets": {"languages": languages, "topics": sorted({t for r in every for t in r["topics"]}),
                       "visibility": sorted({r["visibility"] for r in every if r.get("visibility")})}}


@app.get("/api/users")
def list_users(source: str | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               q: str | None = Query(None, max_length=200)) -> dict[str, Any]:
    return _records("user", source, None, None, limit, offset, q)


@app.get("/api/devices")
def list_devices(source: str | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                 q: str | None = Query(None, max_length=200)) -> dict[str, Any]:
    return _records("device", source, None, None, limit, offset, q)


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    mocks = mock_sources()
    counts = state.db.counts(mocks)
    integrations = list(state.registry.integrations.values())
    connected = sum(1 for c in integrations if c.enabled and _health(c)["status"] in ("healthy", "degraded", "partial"))
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {**counts, "critical": counts["by_severity"].get("critical", 0), "high": counts["by_severity"].get("high", 0),
            "tools_connected": connected, "tools_total": len(integrations), "entities": list(ENTITIES),
            "tables": list(TABLES.values()), "last_24h": state.db.counts_since(since, mocks), "quarantined": state.db.quarantined_total(mocks),
            "hidden_mock_sources": list(mocks)}


@app.get("/api/notifications")
def notifications(limit: int = Query(20, ge=1, le=200)) -> dict[str, Any]:
    return {"items": state.db.list_notifications(limit)}


# ------------------------------------------------------------------ actions
@app.get("/api/actions")
def list_actions() -> dict[str, Any]:
    return {"items": [{"name": a.name, "display_name": a.display_name or a.name, "enabled": a.enabled, "trigger": a.trigger,
                       "when": a.when.model_dump(exclude_none=True), "target": join_url(a.request.base_url, a.request.endpoint),
                       "stats": state.db.action_stats(a.name), "yaml": to_yaml(a)}
                      for a in state.actions.actions.values()],
            "load_errors": state.actions.load_errors}


@app.get("/api/actions/results")
def action_results(action: str | None = None, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    return {"items": state.db.list_action_results(action, limit)}


# ------------------------------------------------------------------ AI mapping
class SuggestIn(BaseModel):
    sample: Any
    entity: str = "event"
    use_llm: bool = True
    link_header: bool = False  # the sample response carried a Link rel="next" header


@app.post("/api/ai/suggest-mapping")
def suggest_mapping(body: SuggestIn) -> dict[str, Any]:
    if body.entity not in ENTITIES:
        raise HTTPException(422, f"entity must be one of: {', '.join(ENTITIES)}")
    try:
        return ai_mapper.suggest_mapping(body.sample, entity=body.entity, use_llm=body.use_llm, link_header=body.link_header)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


class MappingCheckIn(BaseModel):
    sample: Any
    records_path: str | None = None
    mapping: dict[str, str] = {}


@app.post("/api/mapping/check")
def check_mapping(body: MappingCheckIn) -> dict[str, Any]:
    """Per-endpoint path verification: does each mapped JMESPath find a value in the sample records? (no outbound call)"""
    sample = body.sample
    if isinstance(sample, str):
        try:
            sample = json.loads(sample)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, f"Sample is not valid JSON: {exc.msg}")
    try:
        records = [r for r in extract_records(sample, body.records_path or None) if isinstance(r, dict)][:20]
    except Exception as exc:
        return {"records": 0, "error": f"records path: {exc}", "fields": {}}
    fields: dict[str, Any] = {}
    for field, path in body.mapping.items():
        if not path:
            continue
        try:
            jmespath.compile(path)
        except Exception:
            fields[field] = {"ok": False, "error": "not a valid JMESPath expression"}
            continue
        found = []
        for r in records:
            try:
                value = jmes_search(path, r)
            except Exception:
                value = None
            if value not in (None, "", [], {}):
                found.append(value)
        at_run_time = "parent()" in path and not found
        fields[field] = {"ok": bool(found) or at_run_time, "example": found[0] if found else None, "found_in": len(found),
                         "of": len(records), "note": "parent() is filled in at run time" if at_run_time else ""}
    return {"records": len(records), "fields": fields}


# ------------------------------------------------------------------ demo
class DemoIn(BaseModel):
    connector: str | None = None


async def _demo(fn, connector: str | None) -> dict[str, Any]:
    try:
        result = await (fn(state.registry, connector) if connector else fn(state.registry))
    except demo.DemoError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True, "result": result}


@app.post("/api/demo/firewall-429")
async def demo_rate_limit() -> dict[str, Any]:
    """Two 429s on the Demo source (Mock), then success: health shows 'Recovered after 2 retries'."""
    return await _demo(demo.trigger_429, None)


@app.post("/api/demo/retry-after")
async def demo_retry_after() -> dict[str, Any]:
    """One 429 with Retry-After: 5 on the Demo source (Mock): the run waits 5 s, then succeeds."""
    return await _demo(demo.trigger_retry_after, None)


@app.post("/api/demo/malformed")
async def demo_malformed() -> dict[str, Any]:
    """One malformed record from the Demo source (Mock): it is quarantined, the run continues."""
    return await _demo(demo.trigger_malformed, None)


@app.post("/api/demo/bulk-export")
async def demo_bulk_export() -> dict[str, Any]:
    """~20x volume from the Demo source (Mock): the exfiltration guard pauses it and raises a critical alert + ticket."""
    return await _demo(demo.simulate_bulk_export, None)


@app.post("/api/alerts/test")
async def send_test_alert() -> dict[str, Any]:
    """Post 'PlugSec: Slack alerts connected' through the alert channels (admin). Never returns the webhook URL."""
    return await state.registry.alerter.send_test()


@app.post("/api/demo/network-off")
async def demo_network_off(body: DemoIn | None = None) -> dict[str, Any]:
    """One run against a dead address: retries at 1s, 2s, 4s, then FAILED (recorded on the connector's health)."""
    return await _demo(demo.network_off, body.connector if body else None)


@app.post("/api/demo/wrong-key")
async def demo_wrong_key() -> dict[str, Any]:
    """Real GitHub API with an invalid token: real HTTP 401, 'Authentication failed', zero retries, nothing stored."""
    return await _demo(demo.wrong_key, None)


@app.post("/api/demo/repeated-failure")
async def demo_repeated_failure(body: DemoIn | None = None) -> dict[str, Any]:
    """B-4: fail a connector N times in a row (N = alert_after_failures) -> ONE alert; then a normal run -> 'recovered'."""
    return await _demo(demo.repeated_failure, body.connector if body else None)


@app.post("/api/demo/reset")
async def demo_reset() -> dict[str, Any]:
    state.db.delete_revoked_secrets()  # revoked demo secrets come back from .env
    bootstrap_secrets()
    for name, days in parse_age_overrides(os.environ.get("SECRET_AGE_OVERRIDES")).items():
        state.vault.set_age(name, days)
    # Tickets live in the real Jira: the dedupe claims survive a reset, so re-fetched events never open a second ticket.
    demo_mock.reset()
    removed = state.registry.reset_demo()
    return {"ok": True, "removed_integrations": removed}
