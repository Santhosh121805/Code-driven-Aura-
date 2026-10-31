"""Generic engine: runs ANY integration config, stream by stream.

auth -> build request -> paginate -> retries / rate limits (identical for every connector) -> extract records
-> (custom step) -> normalise per entity -> quarantine bad records -> store users / devices / events / repositories.
for_each streams fan out: one request chain per parent record, a bounded number at a time, parents first.
"""
from __future__ import annotations

import asyncio
import email.utils
import importlib
import logging
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urljoin, urlsplit

import httpx
import jmespath
from jinja2 import StrictUndefined, TemplateError, Undefined
from jinja2.sandbox import SandboxedEnvironment

from integration_platform.config import (
    ENTITY_FIELDS, AuthApiKey, AuthBasic, AuthBearer, AuthOAuth2, AuthSessionLogin, IntegrationConfig, MissingSecretError, PaginationCursor,
    PaginationLink, PaginationNone, PaginationOffset, PaginationPage, RateLimitSpec, RetrySpec, Stream, env_refs, lookup_ref,
    resolve_env,
)
from integration_platform import logmask
from integration_platform.logmask import mask_text
from integration_platform.normaliser import BadRecord, normalise, search

log = logging.getLogger("engine")
TRANSIENT_STATUS = {500, 502, 503, 504}
Sleep = Callable[[float], Awaitable[None]]
_jinja = SandboxedEnvironment()
# Endpoint paths of for_each streams: sandboxed, parent-record fields only, every value URL-quoted ('/' kept for owner/repo).
_path_jinja = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False,
                                   finalize=lambda v: quote(str(v), safe="/@:") if v is not None else "")
_oauth_cache: dict[tuple[str, str], tuple[str, float]] = {}  # (token_url, client_id) -> (token, expires_at)
_session_cache: dict[tuple[str, str], tuple[str, float]] = {}  # (login_url, auth config) -> (token, expires_at)


class EngineError(Exception):
    """A run failure with a human-readable message (shown in the health page)."""


class HTTPStatusError(EngineError):
    def __init__(self, message: str, status: int, detail: str = ""):
        super().__init__(message)
        self.status = status
        self.short = f"HTTP {status}: {detail}" if detail else f"HTTP {status}"  # e.g. "HTTP 404: Not Found"


class AuthError(HTTPStatusError):
    """401/403: never retried; health shows 'Authentication failed'."""


class TransientError(EngineError):
    """Timeouts / network / 5xx that still failed after the 1s, 2s, 4s retries."""


class NotConfiguredError(EngineError):
    """A required ${VAR} (secret, domain, repo...) is not set: the connector is 'Not configured', not broken."""


@dataclass
class Stats:
    pages: int = 0
    retries: int = 0
    retry_log: list[str] = field(default_factory=list)
    not_before: float = 0.0  # proactive slow-down: do not send the next request before this time
    last_request: float = 0.0  # for min_interval_seconds pacing


# ---------------------------------------------------------------- HTTP: retries + rate limits
def backoff_seconds(retry: RetrySpec, attempt: int) -> float:
    """Transient-failure backoff: base x 2^attempt (1s, 2s, 4s with the defaults)."""
    delay = retry.base_seconds * (2 ** attempt) if retry.backoff == "exponential" else retry.base_seconds
    return min(delay, retry.max_seconds)


def retry_after_seconds(value: str | None) -> float | None:
    """Retry-After is either delta-seconds or an HTTP date."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _reset_seconds(resp: httpx.Response, rate: RateLimitSpec) -> float | None:
    raw = resp.headers.get(rate.reset_header) if rate.reset_header else None
    try:
        return max(0.0, float(raw) - time.time()) + 1 if raw else None  # +1s: reset epochs are whole seconds
    except ValueError:
        return None


def rate_limit_wait(resp: httpx.Response, rate: RateLimitSpec, retry: RetrySpec, attempt: int) -> tuple[float, str]:
    """How long to wait after a 429, and why: Retry-After > reset header > exponential backoff."""
    backoff = retry.base_seconds * (2 ** attempt)
    seconds = retry_after_seconds(resp.headers.get("Retry-After"))
    if seconds is not None:
        reason = "Retry-After"
    elif (seconds := _reset_seconds(resp, rate)) is not None:
        reason = rate.reset_header or "reset header"
    else:
        seconds, reason = backoff, "exponential backoff (no Retry-After)"
    if seconds < backoff:
        # e.g. NVD answers keyless bursts with "Retry-After: 0": never hammer. Use the API's known window if configured,
        # otherwise at least the normal backoff.
        hint = f"{reason} said {seconds:g}s" if reason == "Retry-After" else "no Retry-After"
        if rate.fallback_wait_seconds:
            seconds, reason = max(backoff, rate.fallback_wait_seconds), f"the rate-limit window ({hint})"
        else:
            seconds, reason = backoff, f"exponential backoff ({hint})"
    return min(round(seconds, 1), rate.max_wait_seconds), reason


def _note_remaining(resp: httpx.Response, rate: RateLimitSpec, stats: Stats) -> None:
    """Proactive slow-down: when the quota is (nearly) used up, hold the next request until the window resets."""
    raw = resp.headers.get(rate.remaining_header) if rate.remaining_header else None
    if raw is None:
        return
    try:
        remaining = int(float(raw))
    except ValueError:
        return
    wait = _reset_seconds(resp, rate)
    if remaining <= rate.min_remaining and wait:
        stats.not_before = time.time() + min(wait, rate.max_wait_seconds)
        stats.retry_log.append(f"{rate.remaining_header}={remaining}: next call waits {min(wait, rate.max_wait_seconds):.0f}s for reset")


async def send_with_retry(client: httpx.AsyncClient, method: str, url: str, retry: RetrySpec, stats: Stats,
                          sleep: Sleep = asyncio.sleep, rate: RateLimitSpec | None = None, **kwargs: Any) -> httpx.Response:
    """Send one request with the platform's standard reliability rules (identical for every connector)."""
    rate = rate or RateLimitSpec()
    attempt = rl_attempt = 0
    while True:
        if stats.not_before > time.time():
            wait = stats.not_before - time.time()
            log.info("rate limit nearly exhausted: waiting %.1fs before calling %s", wait, url)
            await sleep(wait)
        elif rate.min_interval_seconds and stats.last_request:
            gap = stats.last_request + rate.min_interval_seconds - time.time()
            if gap > 0:
                await sleep(gap)
        stats.not_before = 0.0
        stats.last_request = time.time()
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.TimeoutException:
            reason = "timeout"
        except httpx.ConnectError:
            reason = "connection failed (network down or host unreachable)"
        except httpx.TransportError as exc:
            reason = f"network error ({type(exc).__name__})"
        else:
            if resp.status_code == 429:
                if rl_attempt >= rate.max_429_retries:
                    raise HTTPStatusError(f"HTTP 429 rate limited by {url.split('?')[0]} - gave up after {rl_attempt} waits", 429)
                wait, why = rate_limit_wait(resp, rate, retry, rl_attempt)
                rl_attempt += 1
                stats.retries += 1
                stats.retry_log.append(f"HTTP 429: waited {wait:g}s due to {why}")
                log.info("HTTP 429 from %s: waited %gs due to %s", url.split("?")[0], wait, why)
                hold = stats.not_before = max(stats.not_before, time.time() + wait)  # parallel for_each requests wait too
                await sleep(wait)
                if stats.not_before == hold:
                    stats.not_before = 0.0
                continue
            if resp.status_code not in TRANSIENT_STATUS:
                _note_remaining(resp, rate, stats)
                return resp
            reason = f"HTTP {resp.status_code}"
        if attempt >= retry.max_retries:
            waited = ", ".join(f"{backoff_seconds(retry, i):g}s" for i in range(attempt))
            raise TransientError(f"{reason} from {url.split('?')[0]} - FAILED after {attempt} retries" + (f" (waited {waited})" if waited else ""))
        delay = backoff_seconds(retry, attempt)
        attempt += 1
        stats.retries += 1
        stats.retry_log.append(f"{reason} -> retry {attempt} in {delay:g}s")
        log.info("%s %s: %s, retry %d in %gs", method, url.split("?")[0], reason, attempt, delay)
        await sleep(delay)


def _error_detail(resp: httpx.Response) -> str:
    """The API's own short error message (JSON message/error field), for skip reasons like "Dependabot alerts are disabled"."""
    try:
        body = resp.json()
    except ValueError:
        return mask_text(resp.text.strip()[:120])
    if isinstance(body, dict):
        msg = body.get("message") or body.get("error_description") or body.get("error") or body.get("detail")
        if isinstance(msg, str):
            return mask_text(msg.strip()[:160])
    return ""


def check_response(resp: httpx.Response, auth_hint: str = "") -> Any:
    """Raise a clear error for non-2xx responses, else return parsed JSON."""
    url = str(resp.request.url).split("?")[0]
    if resp.status_code in (401, 403):
        raise AuthError(f"Authentication failed: HTTP {resp.status_code} {resp.reason_phrase} from {url} (not retried). {auth_hint}".strip(),
                        resp.status_code, _error_detail(resp))
    if resp.status_code >= 400:
        raise HTTPStatusError(f"HTTP {resp.status_code} from {url}: {resp.text[:200]}", resp.status_code, _error_detail(resp))
    try:
        return resp.json()
    except ValueError:
        raise EngineError(f"Response from {url} is not valid JSON (starts with: {resp.text[:80]!r})")


# ---------------------------------------------------------------- auth
def _auth_hint(auth: Any) -> str:
    refs = sorted(f"${{{name}}}" for name in env_refs(auth.model_dump()))
    return f"Check the value of {', '.join(refs)}." if refs else ""


def clear_oauth_cache() -> None:
    """Forget cached OAuth2 and session-login tokens (after a 401, or when a connector's secret is revoked)."""
    _oauth_cache.clear()
    _session_cache.clear()


def _resolve_deep(value: Any) -> Any:
    """${VAR} references resolved inside nested login bodies."""
    if isinstance(value, str):
        return resolve_env(value)
    if isinstance(value, dict):
        return {k: _resolve_deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_deep(v) for v in value]
    return value


def _optional_missing(ref: str) -> bool:
    name = ref.strip()[2:-1]
    return lookup_ref(name) is None


async def apply_auth(client: httpx.AsyncClient, auth: Any, base_url: str, retry: RetrySpec, stats: Stats,
                     sleep: Sleep = asyncio.sleep, scopes: list[str] | None = None) -> tuple[dict[str, str], httpx.Auth | None]:
    """Return (headers, httpx auth) for the configured auth type. Secrets are resolved here, at runtime only."""
    if isinstance(auth, AuthBearer):
        if auth.optional and _optional_missing(auth.token):
            return {}, None
        return {"Authorization": f"Bearer {resolve_env(auth.token)}"}, None
    if isinstance(auth, AuthApiKey):
        if auth.optional and _optional_missing(auth.api_key):
            return {}, None
        return {auth.header: f"{auth.prefix}{resolve_env(auth.api_key)}"}, None
    if isinstance(auth, AuthBasic):
        return {}, httpx.BasicAuth(resolve_env(auth.username), resolve_env(auth.password))
    if isinstance(auth, AuthOAuth2):
        token_url = auth.token_url if auth.token_url.startswith("http") else base_url + auth.token_url
        client_id = resolve_env(auth.client_id)
        cached = _oauth_cache.get((token_url, client_id))
        if cached and cached[1] > time.time() + 30:
            return {"Authorization": f"Bearer {cached[0]}"}, None
        form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": resolve_env(auth.client_secret)}
        if scopes:
            form["scope"] = " ".join(scopes)
        resp = await send_with_retry(client, "POST", token_url, retry, stats, sleep, data=form)
        body = check_response(resp, _auth_hint(auth))
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise EngineError(f"OAuth2 token endpoint {token_url} did not return an access_token")
        _oauth_cache[(token_url, client_id)] = (token, time.time() + float(body.get("expires_in", 300)))
        return {"Authorization": f"Bearer {token}"}, None
    if isinstance(auth, AuthSessionLogin):
        login_url = auth.login_url if auth.login_url.startswith("http") else base_url + auth.login_url
        key = (login_url, auth.model_dump_json())
        cached = _session_cache.get(key)
        if cached and cached[1] > time.time():
            return {auth.header: f"{auth.prefix}{cached[0]}"}, None
        basic = httpx.BasicAuth(resolve_env(auth.username), resolve_env(auth.password)) if auth.username else None
        send: dict[str, Any] = {"headers": {k: resolve_env(v) for k, v in auth.headers.items()}, "auth": basic}
        if auth.body:
            send["json"] = _resolve_deep(auth.body)
        resp = await send_with_retry(client, auth.method, login_url, retry, stats, sleep, **send)
        if auth.token_response_header:  # e.g. Cisco FMC: the token comes back in a header, the body may be empty
            if resp.status_code >= 400:
                check_response(resp, _auth_hint(auth))  # raises: Authentication failed / HTTP error
            token = resp.headers.get(auth.token_response_header)
        else:
            token = jmespath.search(auth.token_path, check_response(resp, _auth_hint(auth)))
        if not token or not isinstance(token, (str, int)):
            where = f"header {auth.token_response_header}" if auth.token_response_header else f"'{auth.token_path}' in the response"
            raise EngineError(f"Login at {login_url} succeeded but no token was found ({where})")
        token = str(token)
        logmask.remember(token)  # never show the session token in logs or stored errors
        _session_cache[key] = (token, time.time() + auth.ttl_seconds)
        return {auth.header: f"{auth.prefix}{token}"}, None
    return {}, None


# ---------------------------------------------------------------- request building + pagination
def template_context(last_sync: str | None) -> dict[str, Any]:
    """Variables for params: {{ last_sync }}, {{ now }}, and datetime helpers for APIs that need date windows."""
    now = datetime.now(timezone.utc)
    last_dt = datetime.strptime(last_sync, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if last_sync else None
    return {"last_sync": last_sync or "", "last_sync_dt": last_dt, "now": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "now_dt": now,
            "days": lambda n: timedelta(days=n), "minutes": lambda n: timedelta(minutes=n)}


def render_params(params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Render Jinja placeholders like {{ last_sync }} and ${VAR} references; params that render empty are dropped."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            if "{{" in value:
                value = _jinja.from_string(value).render(**context).strip()
            value = resolve_env(value)
            if value == "":
                continue
        out[key] = value
    return out


def extract_records(body: Any, records_path: str | None) -> list[Any]:
    """The list of records in a response. records_path may filter too, e.g. devices[?updateAvailable]."""
    data = search(records_path, body) if records_path else body
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if not isinstance(data, list):
        raise EngineError(f"records_path '{records_path}' points to a {type(data).__name__}, expected a list of records")
    return data  # non-object items are kept as-is so the normaliser can quarantine them


def next_link(resp: httpx.Response, body: Any, p: PaginationLink, base_url: str) -> str | None:
    """Next-page URL from the body (next_path) or the Link header. Refuses other hosts: the token must not leak."""
    url = jmespath.search(p.next_path, body) if p.next_path else resp.links.get("next", {}).get("url")
    if not url:
        return None
    url = urljoin(str(resp.request.url), str(url))
    if urlsplit(url).netloc != urlsplit(base_url).netloc:
        raise EngineError(f"Refusing to follow a next link to another host ({urlsplit(url).netloc}): credentials would be sent there")
    return url


def page_params(p: Any, base: dict[str, Any], index: int, cursor: str | None) -> dict[str, Any]:
    """Query params for page number `index` (0-based) of any pagination type."""
    params = dict(base)
    if isinstance(p, PaginationPage):
        params[p.page_param] = p.start_page + index
        if p.size_param and p.page_size:
            params[p.size_param] = p.page_size
    elif isinstance(p, PaginationOffset):
        params[p.limit_param] = p.limit
        params[p.offset_param] = index * p.limit
    elif isinstance(p, PaginationCursor) and cursor:
        params[p.cursor_param] = cursor
    return params


class ItemError(EngineError):
    """One for_each item could not be requested (e.g. its endpoint template needs a field the record lacks)."""


def render_path(stream: Stream, item: Any) -> str:
    """Endpoint path of one for_each item: {{ repo.full_name }} -> octo/demo. Only the parent record is available."""
    endpoint = resolve_env(stream.endpoint)  # settings first: a parent value can never expand into a ${SECRET}
    if not stream.for_each or "{{" not in endpoint:
        return endpoint
    try:
        path = _path_jinja.from_string(endpoint).render({stream.for_each.as_: item})
    except TemplateError as exc:
        raise ItemError(f"cannot build the path from this record: {exc}")
    if "/../" in f"{path}/" or "/./" in f"{path}/":
        raise ItemError(f"refusing path {path!r}: relative segments are not allowed")
    return path


class _Request:
    """Resolved connection details for one stream (base URL, headers, auth); `item` = parent record of a for_each stream."""

    def __init__(self, cfg: IntegrationConfig, stream: Stream, item: Any = None):
        try:
            self.base_url = resolve_env(cfg.base_url).rstrip("/")
            self.path = render_path(stream, item)
            self.url = self.base_url + self.path
            self.headers = {k: resolve_env(v) for k, v in {**cfg.headers, **stream.headers}.items()}
        except MissingSecretError as exc:
            raise NotConfiguredError(f"Not configured: {exc}")


def _param_context(stream: Stream, last_sync: str | None, item: Any) -> dict[str, Any]:
    context = template_context(last_sync)
    if stream.for_each:
        context[stream.for_each.as_] = item
    return context


async def fetch_records(cfg: IntegrationConfig, stream: Stream, last_sync: str | None = None,
                        transport: httpx.AsyncBaseTransport | None = None, record_limit: int | None = None,
                        sleep: Sleep = asyncio.sleep, stats: Stats | None = None, item: Any = None) -> tuple[list[Any], Stats]:
    """Fetch all pages of one stream (for a for_each stream: of one parent `item`).
    Pass `stats` to keep page/retry counts even when the fetch fails."""
    stats = stats if stats is not None else Stats()
    p = stream.pagination
    max_pages = 1 if isinstance(p, PaginationNone) else p.max_pages
    records: list[Any] = []
    req = _Request(cfg, stream, item)
    try:
        async with httpx.AsyncClient(timeout=stream.timeout_seconds, transport=transport, follow_redirects=True) as client:
            auth_headers, auth = await apply_auth(client, cfg.auth, req.base_url, cfg.retry, stats, sleep, scopes=cfg.scopes)
            headers = {**req.headers, **auth_headers}
            base_params = render_params(stream.params, _param_context(stream, last_sync, item))
            hint = _auth_hint(cfg.auth)
            cursor: str | None = None
            page_url = req.url
            refreshed = False
            for i in range(max_pages):
                # Link pagination: later pages use the server-provided URL as-is. params must be None, not {}:
                # httpx replaces the URL's query string whenever params is passed, which would drop the cursor.
                params = None if isinstance(p, PaginationLink) and i > 0 else page_params(p, base_params, i, cursor)
                body_json = stream.body if stream.method == "POST" else None
                send = dict(params=params, headers=headers, auth=auth, json=body_json)
                resp = await send_with_retry(client, stream.method, page_url, cfg.retry, stats, sleep, cfg.rate_limit, **send)
                if resp.status_code == 401 and isinstance(cfg.auth, (AuthOAuth2, AuthSessionLogin)) and not refreshed:
                    # Cached access token expired or was invalidated server-side: get a fresh one once.
                    refreshed = True
                    clear_oauth_cache()
                    headers.update((await apply_auth(client, cfg.auth, req.base_url, cfg.retry, stats, sleep, scopes=cfg.scopes))[0])
                    resp = await send_with_retry(client, stream.method, page_url, cfg.retry, stats, sleep, cfg.rate_limit, **send)
                body = check_response(resp, hint)
                page_records = extract_records(body, stream.records_path)
                stats.pages += 1
                records.extend(page_records)
                if record_limit and len(records) >= record_limit:
                    break
                # Stop conditions per pagination type.
                if isinstance(p, PaginationPage):
                    total = jmespath.search(p.total_pages_path, body) if p.total_pages_path else None
                    if not page_records or (isinstance(total, (int, float)) and p.start_page + i >= total + p.start_page - 1):
                        break
                elif isinstance(p, PaginationOffset):
                    total = jmespath.search(p.total_path, body) if p.total_path else None
                    if len(page_records) < p.limit or (isinstance(total, (int, float)) and (i + 1) * p.limit >= total):
                        break
                elif isinstance(p, PaginationCursor):
                    cursor = jmespath.search(p.cursor_path, body)
                    if not cursor:
                        break
                elif isinstance(p, PaginationLink):
                    # Stop on an empty page too: Okta's System Log always returns a next link while polling.
                    page_url = next_link(resp, body, p, req.base_url) if page_records else None
                    if not page_url:
                        break
    except MissingSecretError as exc:
        raise NotConfiguredError(f"Not configured: {exc}")
    except httpx.InvalidURL as exc:
        raise EngineError(f"Invalid URL {req.url}: {exc}")
    if cfg.custom_step:
        records = load_custom_step(cfg.custom_step).process(records, cfg)
    return records, stats


async def sample_parent(cfg: IntegrationConfig, stream: Stream, transport: httpx.AsyncBaseTransport | None = None) -> Any:
    """A parent record to try a for_each stream with: the first matching record of the parent's first page."""
    fe = stream.for_each
    parent = cfg.stream(fe.stream)
    body, _ = await fetch_sample(cfg, cfg.streams.index(parent), transport)
    for record in extract_records(body, parent.records_path):
        if not fe.where or search(fe.where, record):
            return record
    raise EngineError(f"{parent.name} returned no record to run {stream.name} for" + (f" (where: {fe.where})" if fe.where else ""))


async def fetch_sample(cfg: IntegrationConfig, stream_index: int = 0, transport: httpx.AsyncBaseTransport | None = None) -> tuple[Any, bool]:
    """Fetch only the first page of one stream (a for_each stream: for the parent's first record).
    Returns (raw JSON body, has a Link rel="next" header)."""
    stream = cfg.streams[stream_index]
    stats = Stats()
    item = await sample_parent(cfg, stream, transport) if stream.for_each else None
    req = _Request(cfg, stream, item)
    try:
        async with httpx.AsyncClient(timeout=stream.timeout_seconds, transport=transport, follow_redirects=True) as client:
            auth_headers, auth = await apply_auth(client, cfg.auth, req.base_url, cfg.retry, stats, scopes=cfg.scopes)
            params = page_params(stream.pagination, render_params(stream.params, _param_context(stream, None, item)), 0, None)
            resp = await send_with_retry(client, stream.method, req.url, cfg.retry, stats, rate=cfg.rate_limit, params=params,
                                         headers={**req.headers, **auth_headers}, auth=auth,
                                         json=stream.body if stream.method == "POST" else None)
            return check_response(resp, _auth_hint(cfg.auth)), "next" in resp.links
    except MissingSecretError as exc:
        raise NotConfiguredError(f"Not configured: {exc}")


# ---------------------------------------------------------------- plugin hook
def load_custom_step(path: str) -> Any:
    """Load `package.module.ClassName`; the class must have `process(records, config) -> records`."""
    module_name, _, class_name = path.rpartition(".")
    try:
        cls = getattr(importlib.import_module(module_name), class_name)
    except (ImportError, AttributeError) as exc:
        raise EngineError(f"custom_step '{path}' could not be loaded: {exc}")
    return cls()


# ---------------------------------------------------------------- exfiltration guard
OnNewEvent = Callable[[dict[str, Any]], Awaitable[None]]


def check_exfiltration(cfg: IntegrationConfig, history: list[int], fetched: int) -> dict[str, Any] | None:
    """Rolling-baseline volume check. Returns details if this run looks like a bulk export with a stolen token."""
    guard = cfg.exfiltration_guard
    if not guard.enabled or len(history) < guard.min_baseline_runs:
        return None
    baseline = statistics.median(history)
    threshold = max(guard.min_records, baseline * guard.multiplier)
    if fetched <= threshold:
        return None
    return {"records": fetched, "baseline": baseline, "threshold": threshold, "multiplier": guard.multiplier,
            "ratio": round(fetched / max(baseline, 1), 1), "baseline_runs": len(history)}


def guard_event(cfg: IntegrationConfig, run_id: int, detail: dict[str, Any], fetched_at: str) -> dict[str, Any]:
    """The critical normalised event raised by the guard; it flows through actions like any other alert."""
    return {
        "entity": "event", "source": cfg.name, "stream": "exfiltration_guard", "id": f"guard-{run_id}",
        "type": "token_abuse", "severity": "critical", "timestamp": fetched_at,
        "description": f"Possible token abuse: abnormal data volume from {cfg.display_name}",
        "host": None, "src_ip": None, "dst_ip": None, "user": None, "fetched_at": fetched_at,
        "raw": {"detector": "exfiltration_guard", "connector": cfg.name, "run_id": run_id, **detail},
    }


# ---------------------------------------------------------------- run / test
def _skip_reason(stream: Stream, unavailable: set[str], parents: dict[str, Any] | None = None) -> str | None:
    missing = [v for v in stream.requires_env if not lookup_ref(v)]
    if missing:
        return f"skipped: {', '.join(missing)} not set"
    if stream.fallback_for and stream.fallback_for not in unavailable:
        return f"skipped: {stream.fallback_for} is available"
    if stream.for_each and parents is not None and stream.for_each.stream not in parents:
        return f"skipped: {stream.for_each.stream} did not run"
    return None


def _is_fallback_target(cfg: IntegrationConfig, stream: Stream) -> bool:
    return any(s.fallback_for == stream.name for s in cfg.streams)


@dataclass
class FanOut:
    """Outcome of one for_each stream: records per parent item, plus items skipped (403/404...) or failed."""
    eligible: int = 0
    results: list[tuple[int, Any, list[Any]]] = field(default_factory=list)  # (item index, parent record, records)
    outcomes: list[tuple[Any, int | str, str]] = field(default_factory=list)  # (parent record, "ok" | HTTP status, reason)
    skipped: list[dict[str, Any]] = field(default_factory=list)  # {item, status, reason}
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {"items": len(self.outcomes) + sum(1 for s in self.skipped if s["status"] is None),
                               "eligible": self.eligible, "skipped": len(self.skipped)}
        if self.skipped:
            reasons: dict[str, int] = {}
            for s in self.skipped:
                reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
            out["skipped_reasons"] = reasons
            out["skipped_items"] = self.skipped[:25]
        if self.errors:
            out["item_errors"] = self.errors[:10]
        return out


def _item_label(stream: Stream, item: Any) -> str:
    try:
        return render_path(stream, item)
    except Exception:
        return stream.endpoint


async def fan_out(cfg: IntegrationConfig, stream: Stream, parents: list[Any], last_sync: str | None,
                  transport: httpx.AsyncBaseTransport | None, sleep: Sleep, stats: Stats,
                  record_limit: int | None = None, max_items: int | None = None) -> FanOut:
    """Run `stream` once per parent record (filtered by for_each.where), at most for_each.concurrency at a time.
    Rate limits, Retry-After and the 1s/2s/4s retries apply to every request (shared `stats` holds the slow-downs).
    Per-item HTTP errors in skip_status are recorded and skipped; 401, exhausted rate limits and network failure
    stop the stream like they would for a normal stream."""
    fe = stream.for_each
    items = [p for p in parents if not fe.where or search(fe.where, p)]
    out = FanOut(eligible=len(items))
    items = items[:min(fe.max_items, max_items or fe.max_items)]
    gate = asyncio.Semaphore(fe.concurrency)
    fatal: list[EngineError] = []

    async def one(index: int, item: Any) -> None:
        async with gate:
            if fatal:
                return
            label = _item_label(stream, item)
            try:
                records, _ = await fetch_records(cfg, stream, last_sync, transport, record_limit, sleep, stats, item=item)
            except ItemError as exc:
                out.skipped.append({"item": label, "status": None, "reason": str(exc)})
            except HTTPStatusError as exc:
                if exc.status in fe.skip_status:
                    out.outcomes.append((item, exc.status, exc.short))
                    out.skipped.append({"item": label, "status": exc.status, "reason": exc.short})
                elif isinstance(exc, AuthError) or exc.status == 429:
                    fatal.append(exc)  # the credential or the quota is the problem: every other item would fail too
                else:
                    out.outcomes.append((item, exc.status, exc.short))
                    out.errors.append(f"{label}: {mask_text(str(exc))}")
            except (TransientError, NotConfiguredError) as exc:
                fatal.append(exc)
            except EngineError as exc:
                out.errors.append(f"{label}: {mask_text(str(exc))}")
            else:
                out.outcomes.append((item, "ok", ""))
                out.results.append((index, item, records))

    await asyncio.gather(*(one(i, item) for i, item in enumerate(items)))
    if fatal:
        raise fatal[0]
    out.results.sort(key=lambda r: r[0])
    return out


_event_jinja = SandboxedEnvironment(undefined=Undefined, autoescape=False)


def new_record_event(cfg: IntegrationConfig, stream: Stream, row: dict[str, Any], fetched_at: str) -> dict[str, Any]:
    """The event a stream's new_record_event raises the first time a record id is seen (e.g. "New device joined")."""
    spec = stream.new_record_event
    fields = {k: row.get(k) for k in ENTITY_FIELDS[stream.entity]}
    text = _event_jinja.from_string(spec.description).render({k: (v if v not in (None, "") else "unknown") for k, v in fields.items()})
    return {
        "entity": "event", "source": cfg.name, "stream": stream.name, "id": f"new:{stream.name}:{row['id']}",
        "type": spec.type, "severity": spec.severity, "timestamp": fetched_at, "description": " ".join(text.split()),
        "host": fields.get("hostname"), "src_ip": fields.get("ip"), "dst_ip": None, "user": fields.get("owner") or fields.get("email"),
        "resource": f"{stream.entity}:{row['id']}", "fetched_at": fetched_at, "raw": {"new_record": fields},
    }


def _relearn_baseline_on_change(cfg: IntegrationConfig, db: Any) -> None:
    """Adding or removing endpoints legitimately changes a connector's volume: re-learn the guard baseline then."""
    previous = db.last_run_streams(cfg.name)
    if previous is not None and set(previous) != {s.name for s in cfg.streams}:
        log.info("%s: endpoints changed (%s -> %s), re-learning the exfiltration-guard baseline",
                 cfg.name, ", ".join(previous), ", ".join(s.name for s in cfg.streams))
        db.restart_baseline(cfg.name)


async def run_integration(cfg: IntegrationConfig, db: Any, on_new_event: OnNewEvent | None = None,
                          transport: httpx.AsyncBaseTransport | None = None, sleep: Sleep = asyncio.sleep) -> dict[str, Any]:
    """Fetch every stream (parents before their for_each children), normalise, quarantine bad records, store
    (deduplicated) and trigger actions for new events. Never raises: errors go to the run record and the health page."""
    run_id = db.start_run(cfg.name)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = Stats()
    _relearn_baseline_on_change(cfg, db)
    history = db.baseline_counts(cfg.name, cfg.exfiltration_guard.baseline_runs)  # before this run is recorded
    streams: list[dict[str, Any]] = []
    errors: list[str] = []
    unavailable: set[str] = set()
    parents: dict[str, list[tuple[Any, str]]] = {}  # stream -> [(raw record, stored id)] fetched this run
    fetched = new = quarantined = skipped_items = 0
    fatal = False
    for stream in cfg.ordered_streams():
        fe = stream.for_each
        result: dict[str, Any] = {"name": stream.name, "entity": stream.entity, "path": stream.endpoint,
                                  "fetched": 0, "new": 0, "updated": 0, "quarantined": 0}
        if fe:
            result["for_each"] = fe.stream
        streams.append(result)
        if fatal:
            result["status"] = "not run"
            continue
        if reason := _skip_reason(stream, unavailable, parents):
            result["status"] = reason
            continue
        fan: FanOut | None = None
        try:
            pages_before = stats.pages
            last_sync = db.get_last_sync(f"{cfg.name}:{stream.name}")
            if fe:
                fan = await fan_out(cfg, stream, [r for r, _ in parents[fe.stream]], last_sync, transport, sleep, stats)
                batches = [(item, records) for _, item, records in fan.results]
            else:
                records, _ = await fetch_records(cfg, stream, last_sync, transport, sleep=sleep, stats=stats)
                batches = [(None, records)]
            result["pages"] = stats.pages - pages_before
        except HTTPStatusError as exc:
            if exc.status in (403, 404) and _is_fallback_target(cfg, stream):
                unavailable.add(stream.name)
                result["status"] = f"not available (HTTP {exc.status}), using fallback"
                continue
            result["status"], result["error"] = "error", mask_text(str(exc))
            errors.append(f"{stream.name}: {result['error']}")
            fatal = isinstance(exc, AuthError)  # every other stream would fail the same way
            continue
        except (TransientError, NotConfiguredError) as exc:
            result["status"], result["error"] = "error", mask_text(str(exc))
            errors.append(f"{stream.name}: {result['error']}")
            fatal = True
            continue
        except EngineError as exc:
            result["status"], result["error"] = "error", mask_text(str(exc))
            errors.append(f"{stream.name}: {result['error']}")
            continue
        except Exception as exc:  # unexpected bug: record it instead of crashing the scheduler
            log.exception("integration %s stream %s crashed", cfg.name, stream.name)
            result["status"], result["error"] = "error", f"Unexpected error: {mask_text(f'{type(exc).__name__}: {exc}')}"
            errors.append(f"{stream.name}: {result['error']}")
            continue
        parent_ids = {id(raw): pid for raw, pid in parents.get(fe.stream, [])} if fe else {}
        parent_entity = cfg.stream(fe.stream).entity if fe else None
        kept: list[tuple[Any, str]] = []
        total = 0
        for parent, records in batches:
            for record in records:
                total += 1
                try:
                    row = normalise(record, stream, cfg.name, started, parent)
                except BadRecord as exc:  # bad data never stops the run: park it with the reason
                    db.quarantine(cfg.name, run_id, record, str(exc), stream.name, stream.entity)
                    result["quarantined"] += 1
                    continue
                if stream.merge_into_parent:
                    merged = db.merge_fields(parent_entity, cfg.name, parent_ids[id(parent)], {f: row[f] for f in stream.mapping}, clear=True)
                    outcome = "updated" if merged else "missing"
                else:
                    outcome = db.store(row, stream.mapping.keys())
                    kept.append((record, row["id"]))
                if outcome in ("new", "updated"):
                    result[outcome] += 1
                if outcome == "new" and stream.entity != "event" and stream.new_record_event:
                    row = new_record_event(cfg, stream, row, started)  # first time this id is seen: raise an event
                    outcome = "new" if db.store(row) == "new" else "duplicate"
                    result["new_events"] = result.get("new_events", 0) + (outcome == "new")
                if outcome == "new" and row["entity"] == "event" and on_new_event:
                    try:
                        await on_new_event(row)
                    except Exception:  # an action failure must never fail ingestion
                        log.exception("action handling failed for %s/%s", row["source"], row["id"])
        parents[stream.name] = kept
        notes: list[str] = []
        if fan:
            if stream.parent_status:
                ps = stream.parent_status
                for parent, outcome, reason in fan.outcomes:
                    matched = next((v for text, v in ps.by_reason.items() if text.lower() in reason.lower()), None)
                    value = ps.ok if outcome == "ok" else matched or ps.by_status.get(outcome)
                    if value:
                        db.merge_fields(parent_entity, cfg.name, parent_ids[id(parent)], {ps.field: value})
            result.update(fan.summary())
            skipped_items += len(fan.skipped)
            notes.append(f"ran for {result['items']} of {fan.eligible} {fe.stream} record(s)")
            if fan.skipped:
                notes.append(f"{len(fan.skipped)} item(s) skipped: " + "; ".join(f"{n} x {r}" for r, n in result["skipped_reasons"].items()))
            if fan.errors:
                result["error"] = f"{len(fan.errors)} item(s) failed: {fan.errors[0]}"
                errors.append(f"{stream.name}: {result['error']}")
        result["fetched"] = total
        result["status"] = "ok"
        if result["quarantined"]:
            notes.append(f"{result['quarantined']} of {total} invalid (quarantined)")
        if notes:
            result["note"] = "; ".join(notes)
        db.set_last_sync(f"{cfg.name}:{stream.name}", started)
        fetched += total
        new += result["new"]
        quarantined += result["quarantined"]

    ok_streams = [s for s in streams if s.get("status") == "ok"]
    suspicious = check_exfiltration(cfg, history, fetched) if ok_streams else None
    if suspicious:
        event = guard_event(cfg, run_id, suspicious, started)
        suspicious["event_id"] = event["id"]
        log.warning("exfiltration guard: %s pulled %d records (baseline %s)", cfg.name, fetched, suspicious["baseline"])
        if db.store(event) == "new" and on_new_event:
            await on_new_event(event)
    if errors and not ok_streams:
        status = "error"
    elif errors:
        status = "partial"
    else:
        status = "suspicious" if suspicious else "success"
    error = "; ".join(errors) or None
    detail = {"streams": streams, "retry_log": stats.retry_log[-20:], "skipped_items": skipped_items}
    if suspicious:
        detail["guard"] = suspicious
    db.finish_run(run_id, status, fetched, new, stats.pages, stats.retries, error, quarantined, detail)
    return {"status": status, "error": error, "records_fetched": fetched, "records_new": new, "pages": stats.pages,
            "retries": stats.retries, "quarantined": quarantined, "suspicious": suspicious, "streams": streams,
            "skipped_items": skipped_items, "retry_log": stats.retry_log}


DRY_RUN_ITEMS = 3  # a test run fans out to the first few parent records only


async def dry_run_integration(cfg: IntegrationConfig, sample_size: int = 5, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """Run every stream once WITHOUT saving: first `sample_size` raw + normalised records per stream
    (for_each streams: for the first few parent records)."""
    streams: list[dict[str, Any]] = []
    unavailable: set[str] = set()
    errors: list[str] = []
    parents: dict[str, list[Any]] = {}
    for stream in cfg.ordered_streams():
        base = {"name": stream.name, "entity": stream.entity, "path": stream.endpoint}
        if reason := _skip_reason(stream, unavailable, parents):
            streams.append({**base, "status": reason})
            continue
        stats = Stats()
        fan: FanOut | None = None
        try:
            if stream.for_each:
                fan = await fan_out(cfg, stream, parents[stream.for_each.stream], None, transport, asyncio.sleep, stats,
                                    record_limit=sample_size, max_items=DRY_RUN_ITEMS)
                batches = [(item, records) for _, item, records in fan.results]
            else:
                records, stats = await fetch_records(cfg, stream, None, transport=transport, record_limit=sample_size, stats=stats)
                batches = [(None, records)]
        except HTTPStatusError as exc:
            if exc.status in (403, 404) and _is_fallback_target(cfg, stream):
                unavailable.add(stream.name)
                streams.append({**base, "status": f"not available (HTTP {exc.status})"})
                continue
            errors.append(f"{stream.name}: {exc}")
            streams.append({**base, "status": "error", "error": str(exc)})
            continue
        except EngineError as exc:
            errors.append(f"{stream.name}: {exc}")
            streams.append({**base, "status": "error", "error": str(exc)})
            continue
        raw, normalised, bad, kept = [], [], [], []
        for parent, records in batches:
            for r in records:
                kept.append(r)
                if len(raw) + len(bad) >= sample_size:
                    continue
                try:
                    row = normalise(r, stream, cfg.name, parent=parent)
                except BadRecord as exc:
                    bad.append({"raw": r, "reason": str(exc)})
                    continue
                row.pop("raw")
                raw.append(r)
                normalised.append(row)
        parents[stream.name] = kept
        entry = {**base, "status": "ok", "raw": raw, "normalised": normalised, "quarantined": bad,
                 "pages": stats.pages, "retries": stats.retries, "retry_log": stats.retry_log}
        if fan:
            entry.update(fan.summary(), for_each=stream.for_each.stream)
            if fan.errors:
                errors.append(f"{stream.name}: {fan.errors[0]}")
        streams.append(entry)
    ok = [s for s in streams if s.get("status") == "ok"]
    if not ok:
        return {"ok": False, "stage": "fetch", "errors": errors or ["No stream could run (check requires_env / fallback settings)"],
                "streams": streams}
    first = ok[0]
    return {"ok": True, "errors": errors, "streams": streams, "raw": first["raw"], "normalised": first["normalised"],
            "quarantined": first["quarantined"], "pages": first["pages"], "retries": first["retries"], "retry_log": first["retry_log"]}
