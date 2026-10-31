"""Integration + action config models (single source of truth), validation and secret resolution.

An integration = shared connection settings (base_url, auth, headers, retry, rate limits, schedule) + one or more
`streams` (endpoints). Each stream pulls one endpoint and maps it to one entity of the common schema: user, device,
event or repository. A stream can fan out (`for_each`): run once per record of another stream, e.g. per repository.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any, Callable, Literal, Union

import jmespath
import yaml
from jinja2 import TemplateSyntaxError, meta
from jinja2.sandbox import SandboxedEnvironment
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from integration_platform import logmask

ROOT = Path(__file__).resolve().parent.parent
INTEGRATIONS_DIR = ROOT / "configs" / "integrations"
ACTIONS_DIR = ROOT / "configs" / "actions"

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# ---------------------------------------------------------------- common schema (PRD minimum + event extras)
Entity = Literal["user", "device", "event", "repository"]
ENTITIES: tuple[str, ...] = ("user", "device", "event", "repository")
ENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "user": ("id", "name", "email", "status", "last_login"),
    "device": ("id", "hostname", "ip", "os", "owner", "last_seen"),
    "event": ("id", "type", "severity", "timestamp", "description", "host", "src_ip", "dst_ip", "user", "resource"),
    "repository": ("id", "full_name", "url", "description", "summary", "summary_source", "topics", "primary_language",
                   "languages", "visibility", "is_fork", "is_archived", "default_branch", "stars", "forks", "open_issues",
                   "created_at", "last_pushed_at", "dependabot_status"),
}
STRUCTURED_FIELDS = {"repository": ("topics", "languages")}  # lists / maps, stored as JSON
TIME_FIELD = {"user": "last_login", "device": "last_seen", "event": "timestamp", "repository": "last_pushed_at"}
DEFAULT_REQUIRED = {"user": ["id"], "device": ["id"], "event": ["id", "timestamp"], "repository": ["id", "full_name"]}
# Must be mapped in config (others have fallbacks: a missing id becomes a content hash, a missing event time = fetch time).
MUST_MAP = {"repository": ["id", "full_name"]}

# ---------------------------------------------------------------- secrets / env references
ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
ENV_REF_ANY = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _must_be_env_ref(value: str) -> str:
    if not ENV_REF.match(value.strip()):
        raise ValueError(
            "must be an environment variable reference like ${MY_TOOL_TOKEN}, not a literal secret. "
            "Put the real value in .env or the vault"
        )
    return value.strip()


SecretRef = Annotated[str, AfterValidator(_must_be_env_ref)]


class MissingSecretError(Exception):
    pass


_secret_lookup: Callable[[str], str | None] | None = None  # set by the encrypted vault at startup


def set_secret_lookup(fn: Callable[[str], str | None] | None) -> None:
    global _secret_lookup
    _secret_lookup = fn


def lookup_ref(name: str) -> str | None:
    """Value of ${name}: encrypted vault first, then the environment. None if unset. Raises if revoked."""
    resolved = _secret_lookup(name) if _secret_lookup else None
    if resolved is None:
        resolved = os.environ.get(name) or None
    return resolved


def resolve_env(value: str) -> str:
    """Replace every ${VAR} in `value` (vault, then environment). Raises MissingSecretError if unset or revoked."""
    def sub(match: re.Match[str]) -> str:
        name = match.group(1)
        resolved = lookup_ref(name)
        if resolved is None:
            raise MissingSecretError(f"Environment variable {name} is not set (add it to .env)")
        logmask.remember(resolved)
        return resolved
    return ENV_REF_ANY.sub(sub, value)


RISKY_SCOPE = re.compile(r"write|admin|manage|delete|owner|root|modify|put|create|update|full|\*|^api$", re.I)


def risky_scopes(scopes: list[str]) -> list[str]:
    """Scopes that look like write/admin access (least privilege says a log connector needs read-only)."""
    return [s for s in scopes if RISKY_SCOPE.search(s)]


def _valid_jmespath(expr: str) -> str:
    try:
        jmespath.compile(expr)
    except Exception:
        raise ValueError(f"is not a valid JMESPath expression: '{expr}' (examples: data.alerts, device.hostname)")
    return expr


JmesPath = Annotated[str, AfterValidator(_valid_jmespath)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- auth
SENSITIVE_HEADER = re.compile(r"auth|token|key|secret|password|cookie", re.I)


def _check_headers(v: dict[str, str]) -> dict[str, str]:
    for name, value in v.items():
        if SENSITIVE_HEADER.search(name) and not ENV_REF.match(value.strip()):
            raise ValueError(f"has a sensitive-looking header '{name}'; its value must be an environment variable reference like ${{MY_TOOL_KEY}}")
    return v


Headers = Annotated[dict[str, str], AfterValidator(_check_headers)]


def _check_login_body(v: dict[str, Any]) -> dict[str, Any]:
    """Secret-looking fields of a login body must be ${NAME} references, like sensitive headers."""
    for name, value in v.items():
        if isinstance(value, dict):
            _check_login_body(value)
        elif SENSITIVE_HEADER.search(name) and not (isinstance(value, str) and ENV_REF.match(value.strip())):
            raise ValueError(f"login body field '{name}' looks secret; its value must be an environment variable reference like ${{MY_TOOL_SECRET}}")
    return v


class AuthNone(_Model):
    type: Literal["none"]


class AuthBearer(_Model):
    type: Literal["bearer"]
    token: SecretRef
    optional: bool = Field(default=False, description="If the secret is not set, call the API unauthenticated")


class AuthApiKey(_Model):
    type: Literal["api_key"]
    header: str = "X-API-Key"
    prefix: str = Field(default="", description='Text before the key, e.g. "SSWS " for Okta API tokens')
    api_key: SecretRef
    optional: bool = Field(default=False, description="If the secret is not set, omit the header (e.g. NVD works slower without a key)")


class AuthBasic(_Model):
    type: Literal["basic"]
    username: str = Field(min_length=1)
    password: SecretRef


class AuthOAuth2(_Model):
    type: Literal["oauth2_client_credentials"]
    token_url: str = Field(description="Full URL, or a path relative to base_url")
    client_id: str = Field(min_length=1)
    client_secret: SecretRef


class AuthSessionLogin(_Model):
    """Log in once, then send the returned token on every request; re-login on expiry or a 401.
    Covers APIs such as Prisma Cloud (/login -> x-redlock-auth), Lacework (/api/v2/access/tokens), Forcepoint DLP
    (refresh-token), Check Point (/web_api/login -> X-chkp-sid) and Cisco FMC (token in a response header)."""
    type: Literal["session_login"]
    login_url: str = Field(description="Full URL, or a path relative to base_url")
    method: Literal["POST", "GET"] = "POST"
    username: str | None = Field(default=None, description="With password: sent as HTTP Basic on the login call only")
    password: SecretRef | None = None
    headers: Headers = Field(default_factory=dict, description="Headers for the login call only, e.g. X-LW-UAKS: ${lw_secret}")
    body: Annotated[dict[str, Any], AfterValidator(_check_login_body)] = Field(
        default_factory=dict, description="JSON body of the login call; strings may reference ${NAME}")
    token_path: JmesPath | None = Field(default="token", description="Where the token is in the JSON response")
    token_response_header: str | None = Field(default=None, description="Take the token from this response header instead")
    header: str = Field(default="Authorization", min_length=1, description="Header that carries the token on later requests")
    prefix: str = Field(default="Bearer ", description='Text before the token, e.g. "Bearer " (empty for x-redlock-auth)')
    ttl_seconds: int = Field(default=600, ge=30, le=86400, description="Re-login after this long (shorter than the token lifetime)")

    @model_validator(mode="after")
    def _token_source(self) -> "AuthSessionLogin":
        if not self.token_path and not self.token_response_header:
            raise ValueError("set token_path (JSON response) or token_response_header (response header)")
        if (self.username is None) != (self.password is None):
            raise ValueError("username and password go together (HTTP Basic on the login call)")
        return self


Auth = Annotated[Union[AuthNone, AuthBearer, AuthApiKey, AuthBasic, AuthOAuth2, AuthSessionLogin], Field(discriminator="type")]
AUTH_TYPES = ("none", "bearer", "api_key", "basic", "oauth2_client_credentials", "session_login")

# ---------------------------------------------------------------- pagination

class PaginationNone(_Model):
    type: Literal["none"]


class PaginationPage(_Model):
    type: Literal["page"]
    page_param: str = "page"
    size_param: str | None = "page_size"
    page_size: int | None = Field(default=None, ge=1, le=5000)
    start_page: int = 1
    total_pages_path: JmesPath | None = Field(default=None, description="JMESPath to total page count, e.g. total_pages")
    max_pages: int = Field(default=10, ge=1, le=1000)


class PaginationOffset(_Model):
    type: Literal["offset"]
    limit_param: str = "limit"
    offset_param: str = "offset"
    limit: int = Field(default=10, ge=1, le=5000)
    total_path: JmesPath | None = Field(default=None, description="JMESPath to the total record count, e.g. totalResults")
    max_pages: int = Field(default=10, ge=1, le=1000)


class PaginationCursor(_Model):
    type: Literal["cursor"]
    cursor_path: JmesPath
    cursor_param: str = "cursor"
    max_pages: int = Field(default=10, ge=1, le=1000)


class PaginationLink(_Model):
    """Follow a "next" URL: from the RFC 8288 Link header (rel="next"), or from the body via next_path."""
    type: Literal["link"]
    next_path: JmesPath | None = Field(default=None, description="JMESPath to the next-page URL in the body; empty = use the Link header")
    max_pages: int = Field(default=10, ge=1, le=1000)


Pagination = Annotated[Union[PaginationNone, PaginationPage, PaginationOffset, PaginationCursor, PaginationLink], Field(discriminator="type")]
PAGINATION_TYPES = ("none", "page", "offset", "cursor", "link")


# ---------------------------------------------------------------- reliability (identical for every connector)
class RetrySpec(_Model):
    """Timeouts, connection errors and 5xx: retry with backoff base x 2^n (1s, 2s, 4s), then fail the run."""
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff: Literal["exponential", "fixed"] = "exponential"
    base_seconds: float = Field(default=1, ge=0, le=60)
    max_seconds: float = Field(default=30, ge=0, le=300)


class RateLimitSpec(_Model):
    """429 handling + proactive slow-down. Retry-After always wins; reset_header is the fallback (epoch seconds)."""
    reset_header: str | None = Field(default=None, description="Header with the epoch second the window resets, e.g. x-ratelimit-reset")
    remaining_header: str | None = Field(default=None, description="Header with requests left in the window, e.g. x-ratelimit-remaining")
    min_remaining: int = Field(default=1, ge=0, description="Wait for the reset before the next call when remaining <= this")
    max_wait_seconds: float = Field(default=120, ge=0, le=3600, description="Never sleep longer than this for one rate-limit wait")
    max_429_retries: int = Field(default=5, ge=0, le=20)
    min_interval_seconds: float = Field(default=0, ge=0, le=60, description="Pace requests: at least this long between calls (NVD asks for 6s without a key)")
    fallback_wait_seconds: float = Field(default=0, ge=0, le=3600,
                                         description="Wait this long after a 429 that carries no useful hint (e.g. NVD's 30 s rolling window)")


class GuardSpec(_Model):
    """Exfiltration guard: flag a run that pulls far more records than this connector's normal volume."""
    enabled: bool = True
    multiplier: float = Field(default=5, gt=1, le=1000, description="Suspicious when records > multiplier x baseline")
    min_records: int = Field(default=50, ge=1, description="Never flag runs below this size (avoids noise on tiny feeds)")
    baseline_runs: int = Field(default=10, ge=1, le=100, description="Rolling window of successful runs used as the baseline")
    min_baseline_runs: int = Field(default=3, ge=1, le=100, description="Runs needed before the guard is active")


class Transforms(_Model):
    severity_map: dict[str, Severity] = Field(default_factory=dict)
    time_format: Literal["iso8601", "epoch_s", "epoch_ms"] = "iso8601"
    default_severity: Severity = "info"


# ---------------------------------------------------------------- streams
def _slug(v: str, example: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,48}", v):
        raise ValueError(f"must be 2-49 chars of lowercase letters, digits or underscores, starting with a letter (e.g. {example})")
    return v


PARAM_VARIABLES = {"last_sync", "last_sync_dt", "now", "now_dt", "days", "minutes"}  # see engine.template_context
_jinja_vars = SandboxedEnvironment()


def template_variables(text: str) -> set[str]:
    """Top-level variables a Jinja template uses, e.g. {"repo"} for "/repos/{{ repo.full_name }}"."""
    try:
        return meta.find_undeclared_variables(_jinja_vars.parse(text))
    except TemplateSyntaxError as exc:
        raise ValueError(f"template syntax error: {exc.message}")


class ForEach(_Model):
    """Fan-out: run this stream once per record of another stream of the same integration (the parent runs first).
    The endpoint and params may use the parent record, e.g. path: /repos/{{ repo.full_name }}/languages."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)
    stream: str = Field(description="Parent stream, e.g. repositories")
    as_: str = Field(default="item", alias="as", description="Name of the parent record in templates, e.g. repo")
    where: JmesPath | None = Field(default=None, description="Only parent records matching this JMESPath condition, e.g. !description")
    concurrency: int = Field(default=4, ge=1, le=16, description="Parallel requests (rate limits and retries still apply)")
    skip_status: list[int] = Field(default_factory=lambda: [403, 404],
                                   description="Per-item HTTP errors that are recorded and skipped instead of failing the stream")
    max_items: int = Field(default=500, ge=1, le=5000, description="Never fan out to more parent records than this per run")

    @field_validator("as_")
    @classmethod
    def _as(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,30}", v) or v in PARAM_VARIABLES:
            raise ValueError(f"must be a short lowercase name such as repo or item (not {', '.join(sorted(PARAM_VARIABLES))})")
        return v


class ParentStatus(_Model):
    """Write each fan-out item's outcome into a field of its parent record, e.g. dependabot_status: enabled / disabled."""
    field: str
    ok: str = "ok"
    by_status: dict[int, str] = Field(default_factory=dict, description="HTTP status -> value, e.g. {403: disabled, 404: no access}")
    by_reason: dict[str, str] = Field(default_factory=dict,
                                      description="Checked first: text in the API's error message -> value, e.g. {not accessible: no access}")


class Stream(_Model):
    name: str = Field(description="Stream id within the integration, e.g. users or events")
    entity: Entity = "event"
    endpoint: str = Field(min_length=1, description="Path after base_url (also accepted as `path`)")
    method: Literal["GET", "POST"] = "GET"
    params: dict[str, Any] = Field(default_factory=dict)
    headers: Headers = Field(default_factory=dict)
    body: dict[str, Any] | None = None
    timeout_seconds: float = Field(default=15, gt=0, le=120)
    pagination: Pagination = Field(default_factory=lambda: PaginationNone(type="none"))
    records_path: JmesPath | None = Field(default=None, description="JMESPath to the list of records; empty = whole response")
    mapping: dict[str, JmesPath]
    required_fields: list[str] | None = Field(default=None, description="Default: id (+ timestamp for events)")
    transforms: Transforms = Field(default_factory=Transforms)
    requires_env: list[str] = Field(default_factory=list, description="Skip this stream unless these variables are set (e.g. GITHUB_ORG)")
    fallback_for: str | None = Field(default=None, description="Only run when the named stream was unavailable (HTTP 403/404) this run")
    for_each: ForEach | None = Field(default=None, description="Run once per record of another stream")
    merge_into_parent: bool = Field(default=False, description="Merge the mapped fields into the parent record instead of adding rows")
    parent_status: ParentStatus | None = Field(default=None, description="Record each item's outcome in a parent field")

    @model_validator(mode="before")
    @classmethod
    def _path_alias(cls, data: Any) -> Any:
        if isinstance(data, dict) and "path" in data:
            data = dict(data)
            if "endpoint" in data:
                raise ValueError("set either endpoint or path, not both")
            data["endpoint"] = data.pop("path")
        return data

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _slug(v, "users")

    @field_validator("endpoint")
    @classmethod
    def _slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("must start with '/', e.g. /api/v1/users")
        return v

    @model_validator(mode="after")
    def _fields_match_entity(self) -> "Stream":
        allowed = ENTITY_FIELDS[self.entity]
        if not self.mapping:
            raise ValueError("mapping needs at least one field, e.g. id: uuid")
        bad = [f for f in self.mapping if f not in allowed]
        if bad:
            raise ValueError(f"mapping field(s) {', '.join(bad)} are not part of the {self.entity} schema; use: {', '.join(allowed)}")
        bad = [f for f in (self.required_fields or []) if f not in allowed]
        if bad:
            raise ValueError(f"required_fields {', '.join(bad)} are not part of the {self.entity} schema")
        if not self.merge_into_parent:
            unmapped = [f for f in (self.required_fields or MUST_MAP.get(self.entity, [])) if f not in self.mapping]
            if unmapped:
                raise ValueError(f"a {self.entity} needs {', '.join(unmapped)} mapped (required field)")
        # Templating is sandboxed and may only use the parent record: no settings, no other data.
        used = template_variables(self.endpoint)
        allowed_vars = {self.for_each.as_} if self.for_each else set()
        if used - allowed_vars:
            hint = f"only {{{{ {self.for_each.as_}.<field> }}}} is available" if self.for_each else \
                "placeholders need for_each (run for each record of another stream)"
            raise ValueError(f"endpoint uses {', '.join(sorted(used - allowed_vars))}: {hint}")
        for key, value in self.params.items():
            if isinstance(value, str) and "{{" in value:
                extra = template_variables(value) - PARAM_VARIABLES - allowed_vars
                if extra:
                    raise ValueError(f"param {key} uses unknown variable(s) {', '.join(sorted(extra))}")
        if (self.merge_into_parent or self.parent_status) and not self.for_each:
            raise ValueError("merge_into_parent and parent_status need for_each")
        return self

    @property
    def required(self) -> list[str]:
        return self.required_fields if self.required_fields is not None else DEFAULT_REQUIRED[self.entity]


# ---------------------------------------------------------------- integration
class IntegrationConfig(_Model):
    name: str = Field(description="Unique id: lowercase letters, digits, underscores")
    display_name: str = Field(min_length=1)
    enabled: bool = True
    base_url: str = Field(description="May reference .env, e.g. https://${OKTA_DOMAIN}")
    auth: Auth
    scopes: list[str] = Field(default_factory=list, description="Permissions the credential holds (requested at the token endpoint for OAuth2)")
    headers: Headers = Field(default_factory=dict, description="Sent with every request of every stream")
    schedule_seconds: int = Field(default=900, ge=5, le=86400, description="Run every N seconds (900 = 15 minutes)")
    retry: RetrySpec = Field(default_factory=RetrySpec)
    rate_limit: RateLimitSpec = Field(default_factory=RateLimitSpec)
    streams: list[Stream] = Field(min_length=1)
    secret_max_age_days: int = Field(default=90, ge=1, le=3650, description="Health warns 'Rotate secret' after this many days")
    alert_after_failures: int = Field(default=3, ge=1, le=100, description="Alert once after this many consecutive failed runs")
    exfiltration_guard: GuardSpec = Field(default_factory=GuardSpec)
    custom_step: str | None = Field(default=None, description="Optional plugin 'module.ClassName' for cases config cannot express")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _slug(v, "okta")

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        if not re.match(r"^https?://[^\s/]+", v) and not ENV_REF.match(v):
            raise ValueError("must start with http:// or https:// (it may reference .env, e.g. https://${OKTA_DOMAIN})")
        return v.rstrip("/")

    @field_validator("custom_step")
    @classmethod
    def _custom_step(cls, v: str | None) -> str | None:
        if v and not re.fullmatch(r"[A-Za-z_][\w.]*\.[A-Za-z_]\w*", v):
            raise ValueError("must look like 'package.module.ClassName'")
        return v or None

    @model_validator(mode="after")
    def _streams_consistent(self) -> "IntegrationConfig":
        names = [s.name for s in self.streams]
        if len(names) != len(set(names)):
            raise ValueError(f"stream names must be unique (got {', '.join(names)})")
        by_name = {s.name: s for s in self.streams}
        for s in self.streams:
            if s.fallback_for and s.fallback_for not in names:
                raise ValueError(f"stream {s.name}: fallback_for '{s.fallback_for}' is not a stream of this integration")
            if not s.for_each:
                continue
            parent = by_name.get(s.for_each.stream)
            if parent is None or parent is s:
                raise ValueError(f"stream {s.name}: for_each stream '{s.for_each.stream}' must be another stream of this integration")
            if (s.merge_into_parent or s.parent_status) and parent.entity == "event":
                raise ValueError(f"stream {s.name}: events are immutable, so it cannot write into its parent '{parent.name}'")
            if s.merge_into_parent and s.entity != parent.entity:
                raise ValueError(f"stream {s.name}: merge_into_parent needs entity {parent.entity} (the parent's)")
            if s.parent_status and s.parent_status.field not in ENTITY_FIELDS[parent.entity]:
                raise ValueError(f"stream {s.name}: parent_status field '{s.parent_status.field}' is not a {parent.entity} field")
        self.ordered_streams()  # raises on a for_each cycle
        return self

    def stream(self, name: str) -> Stream:
        return next(s for s in self.streams if s.name == name)

    def ordered_streams(self) -> list[Stream]:
        """Streams in run order: config order, except that a for_each stream always runs after its parent."""
        by_name = {s.name: s for s in self.streams}
        done: list[Stream] = []
        visiting: set[str] = set()

        def visit(s: Stream) -> None:
            if s in done:
                return
            if s.name in visiting:
                raise ValueError(f"for_each streams form a cycle at '{s.name}'")
            visiting.add(s.name)
            if s.for_each and s.for_each.stream in by_name:
                visit(by_name[s.for_each.stream])
            visiting.discard(s.name)
            done.append(s)

        for s in self.streams:
            visit(s)
        return done


def env_refs(value: Any) -> set[str]:
    """All ${VAR} names referenced anywhere inside a config value (dicts/lists walked recursively)."""
    if isinstance(value, str):
        return set(ENV_REF_ANY.findall(value))
    if isinstance(value, dict):
        return set().union(*(env_refs(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(env_refs(v) for v in value)) if value else set()
    return set()


def missing_settings(cfg: IntegrationConfig) -> list[str]:
    """Required ${VAR}s (auth secrets, base_url, headers, endpoints, params) that are not set. Empty = configured.
    Optional auth secrets and the requires_env of optional streams do not count."""
    data = cfg.model_dump(mode="json")
    auth = dict(data["auth"])
    if auth.get("optional"):
        auth = {}
    needed = env_refs(auth) | env_refs(data["base_url"]) | env_refs(data["headers"])
    for s in data["streams"]:
        if all(lookup_ref(v) for v in s["requires_env"]):
            needed |= env_refs({k: s[k] for k in ("endpoint", "params", "headers")})
    missing = []
    for name in sorted(needed):
        try:
            if lookup_ref(name) is None:
                missing.append(name)
        except MissingSecretError:
            pass  # revoked secrets are reported by the connector state, not as "not configured"
    return missing


# ---------------------------------------------------------------- actions
class ActionWhen(_Model):
    severity_in: list[Severity] | None = None
    source_in: list[str] | None = None
    type_not_in: list[str] | None = Field(default=None, description="Never fire for these event types, e.g. dependabot_alert")


class ActionRequest(_Model):
    base_url: str
    endpoint: str
    method: Literal["POST", "PUT", "PATCH"] = "POST"
    auth: Auth
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=10, gt=0, le=120)


_jinja_check = SandboxedEnvironment()


def _valid_template(v: str) -> str:
    try:
        _jinja_check.parse(v)
    except TemplateSyntaxError as exc:
        raise ValueError(f"template syntax error on line {exc.lineno}: {exc.message}")
    return v


ActionTrigger = Literal["event", "connector_failure", "connector_recovered", "connector_test"]


class ActionConfig(_Model):
    name: str
    display_name: str | None = None
    enabled: bool = True
    trigger: list[ActionTrigger] = Field(default_factory=lambda: ["event"],
                                         description="event = each new event; connector_failure / connector_recovered = B-4 alerts; connector_test = test message")
    when: ActionWhen = Field(default_factory=ActionWhen)
    request: ActionRequest
    body_template: Annotated[str, AfterValidator(_valid_template)]
    dedupe_key: Annotated[str, AfterValidator(_valid_template)]
    response_ticket_path: JmesPath | None = None
    retry: RetrySpec = Field(default_factory=RetrySpec)


# ---------------------------------------------------------------- friendly errors
_TAG_PARENTS = {"auth", "pagination"}
_TAG_VALUES = set(AUTH_TYPES) | set(PAGINATION_TYPES)


def _loc(loc: tuple[Any, ...]) -> str:
    parts: list[str] = []
    prev: Any = None
    for item in loc:
        # Discriminated unions insert the tag (e.g. 'bearer') into the path; hide it.
        if prev in _TAG_PARENTS and item in _TAG_VALUES:
            prev = item
            continue
        if item == "[key]":
            continue
        parts.append(str(item))
        prev = item
    return ".".join(parts) or "config"


def friendly_errors(exc: ValidationError) -> list[str]:
    messages: list[str] = []
    for err in exc.errors():
        loc, kind, ctx = _loc(err["loc"]), err["type"], err.get("ctx") or {}
        if kind == "union_tag_invalid" or kind == "union_tag_not_found":
            options = AUTH_TYPES if loc.split(".")[-1] == "auth" else PAGINATION_TYPES
            msg = f"{loc}.type must be one of: {', '.join(options)}"
        elif kind == "missing":
            msg = f"{loc} is required"
        elif kind == "extra_forbidden":
            msg = f"{loc} is not a recognised field (check spelling)"
        elif kind == "literal_error":
            expected = ctx.get("expected", "").replace("'", "")
            msg = f"{loc} must be one of: {expected.replace(' or ', ', ')}"
        elif kind == "too_short" and loc == "streams":
            msg = "streams needs at least one stream"
        elif kind.endswith("_type") or kind.endswith("_parsing"):
            msg = f"{loc}: {err['msg'].lower()}"
        else:
            text = err["msg"].removeprefix("Value error, ")
            msg = f"{loc} {text}" if loc != "config" else text
        if msg not in messages:
            messages.append(msg)
    return messages


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def parse_yaml(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        raise ConfigError([f"YAML syntax error{where}: {getattr(exc, 'problem', exc)}"])
    if not isinstance(data, dict):
        raise ConfigError(["Config must be a YAML/JSON object (key: value pairs)"])
    return data


def validate_integration(data: dict[str, Any]) -> IntegrationConfig:
    try:
        return IntegrationConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(friendly_errors(exc))


def validate_action(data: dict[str, Any]) -> ActionConfig:
    try:
        return ActionConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(friendly_errors(exc))


def to_yaml(model: BaseModel) -> str:
    return yaml.safe_dump(model.model_dump(mode="json", exclude_none=True), sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------- files
def load_integration_files() -> tuple[dict[str, IntegrationConfig], dict[str, list[str]]]:
    """Load all integration YAMLs. Returns (valid configs, {filename: errors}) - a bad file never stops the rest."""
    configs: dict[str, IntegrationConfig] = {}
    errors: dict[str, list[str]] = {}
    for path in sorted(INTEGRATIONS_DIR.glob("*.yaml")):
        try:
            cfg = validate_integration(parse_yaml(path.read_text(encoding="utf-8")))
            configs[cfg.name] = cfg
        except ConfigError as exc:
            errors[path.name] = exc.errors
    return configs, errors


def load_action_files() -> tuple[dict[str, ActionConfig], dict[str, list[str]]]:
    configs: dict[str, ActionConfig] = {}
    errors: dict[str, list[str]] = {}
    for path in sorted(ACTIONS_DIR.glob("*.yaml")):
        try:
            cfg = validate_action(parse_yaml(path.read_text(encoding="utf-8")))
            configs[cfg.name] = cfg
        except ConfigError as exc:
            errors[path.name] = exc.errors
    return configs, errors


def save_integration_file(cfg: IntegrationConfig) -> Path:
    INTEGRATIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = INTEGRATIONS_DIR / f"{cfg.name}.yaml"
    path.write_text(to_yaml(cfg), encoding="utf-8")
    return path
