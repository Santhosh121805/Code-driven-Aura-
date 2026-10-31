"""FastAPI app: REST API + static single-page UI. Run: uvicorn integration_platform.api:app"""
from __future__ import annotations

import copy
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from integration_platform.config import (
    ENTITIES, ENTITY_FIELDS, ROOT, ActionConfig, ConfigError, IntegrationConfig, MissingSecretError, load_action_files,
    load_integration_files, missing_settings, parse_yaml, resolve_env, risky_scopes, to_yaml, validate_integration,
)

ENV_FILE = os.environ.get("INTEGRATION_HUB_ENV_FILE", str(ROOT / ".env"))  # tests set this to "" to stay hermetic
if ENV_FILE:
    load_dotenv(ENV_FILE, override=False)  # before anything reads secrets

from integration_platform import ai_mapper, auth, demo, logmask  # noqa: E402
from integration_platform.actions import ActionRunner  # noqa: E402
from integration_platform.alerts import FailureAlerter  # noqa: E402
from integration_platform.db import TABLES, Database  # noqa: E402
from integration_platform.engine import EngineError, dry_run_integration, fetch_sample  # noqa: E402
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


app = FastAPI(title="Config-Driven Integration Platform", version="2.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.exception_handler(ConfigError)
async def _config_error(_, exc: ConfigError) -> JSONResponse:
    return JSONResponse({"ok": False, "stage": "validation", "errors": exc.errors}, status_code=422)


# ------------------------------------------------------------------ sign-in, roles, audit
PUBLIC_API = {"/api/auth/login", "/api/auth/logout"}
AUDIT_SKIP = {"/api/integrations/validate", "/api/convert"}  # pure computations: no state change, no outbound call
AUDIT_LABELS = {
    ("POST", "/api/integrations"): "Created integration", ("PUT", "/api/integrations/{name}"): "Updated integration",
    ("DELETE", "/api/integrations/{name}"): "Deleted integration", ("POST", "/api/integrations/{name}/enable"): "Enabled integration",
    ("POST", "/api/integrations/{name}/disable"): "Disabled integration", ("POST", "/api/integrations/{name}/resume"): "Resumed integration",
    ("POST", "/api/integrations/{name}/revoke"): "Revoked secrets", ("POST", "/api/integrations/{name}/run"): "Ran integration",
    ("POST", "/api/integrations/test"): "Tested connection", ("POST", "/api/integrations/sample"): "Fetched sample",
    ("POST", "/api/secrets"): "Stored secret", ("POST", "/api/ai/suggest-mapping"): "Suggested mapping",
    ("POST", "/api/demo/network-off"): "Demo: network off", ("POST", "/api/demo/wrong-key"): "Demo: wrong key",
    ("POST", "/api/demo/repeated-failure"): "Demo: repeated failure", ("POST", "/api/demo/reset"): "Reset demo",
}


def _audit(user: str, role: str | None, action: str, target: str | None, outcome: str) -> None:
    try:
        state.db.add_audit(user, role, action, target, outcome)
    except Exception:  # auditing must never break the request (e.g. DB not ready in a unit test)
        log.exception("could not write audit entry")


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
        label = AUDIT_LABELS.get((request.method, template), f"{request.method} {template}")
        target = request.scope.get("path_params", {}).get("name")  # filled in by the router during call_next
        _audit(session["user"], session["role"], label, target, "ok" if response.status_code < 400 else f"failed ({response.status_code})")
    return response


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response) -> dict[str, Any]:
    client = request.client.host if request.client else "unknown"
    if auth.throttled(client):
        raise HTTPException(429, "Too many failed sign-ins. Wait a minute and try again.")
    role = auth.authenticate(body.username, body.password)
    if role is None:
        auth.note_failure(client)
        _audit(body.username[:64] or "?", None, "Sign-in failed", None, "denied")
        raise HTTPException(401, "Wrong username or password")
    response.set_cookie(auth.COOKIE, auth.issue_session(body.username, role), max_age=auth.SESSION_SECONDS,
                        httponly=True, samesite="lax", secure=request.url.scheme == "https", path="/")
    _audit(body.username, role, "Signed in", None, "ok")
    return {"user": body.username, "role": role}


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


def _summary(cfg: IntegrationConfig) -> dict[str, Any]:
    return {
        "name": cfg.name, "display_name": cfg.display_name, "enabled": cfg.enabled, "base_url": cfg.base_url,
        "auth_type": cfg.auth.type, "schedule_seconds": cfg.schedule_seconds,
        "streams": [{"name": s.name, "entity": s.entity, "endpoint": s.endpoint, "pagination": s.pagination.type} for s in cfg.streams],
        "seeded": cfg.name in SEEDED_INTEGRATIONS, "scopes": cfg.scopes, "risky_scopes": risky_scopes(cfg.scopes),
        "health": _health(cfg),
    }


def _get(name: str) -> IntegrationConfig:
    cfg = state.registry.integrations.get(name)
    if cfg is None:
        raise HTTPException(404, f"Integration '{name}' not found")
    return cfg


# ------------------------------------------------------------------ meta
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


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
        out["guard_event"] = state.db.get_event(name, st["detail"]["event_id"])
    return out


@app.post("/api/integrations", status_code=201)
def create_integration(body: ConfigIn, overwrite: bool = False) -> dict[str, Any]:
    cfg = body.to_config()
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
        s["mapping"] = s.get("mapping") or {"id": "@"}  # placeholder: mapping is decided after seeing the sample
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
def store_secret(body: SecretIn) -> dict[str, Any]:
    """Store (or rotate) a secret encrypted at rest. The value is never returned; configs reference ${NAME}."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", body.name) or not body.value:
        raise HTTPException(422, "name must look like MY_TOOL_TOKEN and value must not be empty")
    state.vault.set(body.name, body.value)
    logmask.remember(body.value)
    return {"ok": True, "reference": f"${{{body.name}}}", **state.vault.info(body.name)}


# ------------------------------------------------------------------ common-schema data (one place, FR-11)
def _records(entity: str, source: str | None, severity: str | None, type_: str | None, limit: int, offset: int,
             q: str | None = None, since: str | None = None) -> dict[str, Any]:
    items, total = state.db.list_records(entity, source or None, severity or None, type_ or None, limit, offset,
                                         q=(q or "").strip() or None, since=since or None)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.get("/api/events")
def list_events(source: str | None = None, severity: str | None = None, type: str | None = None,  # noqa: A002
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                q: str | None = Query(None, max_length=200), since: str | None = None) -> dict[str, Any]:
    """`q` searches id/type/description/host/IPs/user/ticket; `since` (ISO 8601 UTC) keeps events at or after it."""
    return _records("event", source, severity, type, limit, offset, q, since)


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
    counts = state.db.counts()
    integrations = list(state.registry.integrations.values())
    connected = sum(1 for c in integrations if c.enabled and _health(c)["status"] in ("healthy", "degraded", "partial"))
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {**counts, "critical": counts["by_severity"].get("critical", 0), "high": counts["by_severity"].get("high", 0),
            "tools_connected": connected, "tools_total": len(integrations), "entities": list(ENTITIES),
            "tables": list(TABLES.values()), "last_24h": state.db.counts_since(since), "quarantined": state.db.quarantined_total()}


@app.get("/api/notifications")
def notifications(limit: int = Query(20, ge=1, le=200)) -> dict[str, Any]:
    return {"items": state.db.list_notifications(limit)}


# ------------------------------------------------------------------ actions
@app.get("/api/actions")
def list_actions() -> dict[str, Any]:
    return {"items": [{"name": a.name, "display_name": a.display_name or a.name, "enabled": a.enabled, "trigger": a.trigger,
                       "when": a.when.model_dump(exclude_none=True), "target": a.request.base_url + a.request.endpoint,
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


# ------------------------------------------------------------------ demo
class DemoIn(BaseModel):
    connector: str | None = None


async def _demo(fn, connector: str | None) -> dict[str, Any]:
    try:
        result = await (fn(state.registry, connector) if connector else fn(state.registry))
    except demo.DemoError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True, "result": result}


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
    removed = state.registry.reset_demo()
    return {"ok": True, "removed_integrations": removed}
