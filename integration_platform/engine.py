"""Generic engine: runs ANY integration config, stream by stream.

auth -> build request -> paginate -> retries / rate limits (identical for every connector) -> extract records
-> (custom step) -> normalise per entity -> quarantine bad records -> store users / devices / events.
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
from urllib.parse import urljoin, urlsplit

import httpx
import jmespath
from jinja2.sandbox import SandboxedEnvironment

from integration_platform.config import (
    AuthApiKey, AuthBasic, AuthBearer, AuthOAuth2, IntegrationConfig, MissingSecretError, PaginationCursor,
    PaginationLink, PaginationNone, PaginationOffset, PaginationPage, RateLimitSpec, RetrySpec, Stream, lookup_ref,
    resolve_env,
)
from integration_platform.logmask import mask_text
from integration_platform.normaliser import BadRecord, normalise

log = logging.getLogger("engine")
TRANSIENT_STATUS = {500, 502, 503, 504}
Sleep = Callable[[float], Awaitable[None]]
_jinja = SandboxedEnvironment()
_oauth_cache: dict[tuple[str, str], tuple[str, float]] = {}  # (token_url, client_id) -> (token, expires_at)


class EngineError(Exception):
    """A run failure with a human-readable message (shown in the health page)."""


class HTTPStatusError(EngineError):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


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
    seconds = retry_after_seconds(resp.headers.get("Retry-After"))
    if seconds is not None:
        reason = "Retry-After"
    elif (seconds := _reset_seconds(resp, rate)) is not None:
        reason = rate.reset_header or "reset header"
    else:
        seconds, reason = retry.base_seconds * (2 ** attempt), "exponential backoff (no Retry-After)"
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
                await sleep(wait)
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


def check_response(resp: httpx.Response, auth_hint: str = "") -> Any:
    """Raise a clear error for non-2xx responses, else return parsed JSON."""
    url = str(resp.request.url).split("?")[0]
    if resp.status_code in (401, 403):
        raise AuthError(f"Authentication failed: HTTP {resp.status_code} {resp.reason_phrase} from {url} (not retried). {auth_hint}".strip(),
                        resp.status_code)
    if resp.status_code >= 400:
        raise HTTPStatusError(f"HTTP {resp.status_code} from {url}: {resp.text[:200]}", resp.status_code)
    try:
        return resp.json()
    except ValueError:
        raise EngineError(f"Response from {url} is not valid JSON (starts with: {resp.text[:80]!r})")


# ---------------------------------------------------------------- auth
def _auth_hint(auth: Any) -> str:
    refs = [v for k, v in auth.model_dump().items() if isinstance(v, str) and v.startswith("${")]
    return f"Check the value of {', '.join(refs)}." if refs else ""


def clear_oauth_cache() -> None:
    """Forget cached OAuth2 access tokens (after a 401, or when a connector's secret is revoked)."""
    _oauth_cache.clear()


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
    data = jmespath.search(records_path, body) if records_path else body
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


class _Request:
    """Resolved connection details for one stream (base URL, headers, auth)."""

    def __init__(self, cfg: IntegrationConfig, stream: Stream):
        try:
            self.base_url = resolve_env(cfg.base_url).rstrip("/")
            self.url = self.base_url + resolve_env(stream.endpoint)
            self.headers = {k: resolve_env(v) for k, v in {**cfg.headers, **stream.headers}.items()}
        except MissingSecretError as exc:
            raise NotConfiguredError(f"Not configured: {exc}")


async def fetch_records(cfg: IntegrationConfig, stream: Stream, last_sync: str | None = None,
                        transport: httpx.AsyncBaseTransport | None = None, record_limit: int | None = None,
                        sleep: Sleep = asyncio.sleep, stats: Stats | None = None) -> tuple[list[Any], Stats]:
    """Fetch all pages of one stream. Pass `stats` to keep page/retry counts even when the fetch fails."""
    stats = stats if stats is not None else Stats()
    p = stream.pagination
    max_pages = 1 if isinstance(p, PaginationNone) else p.max_pages
    records: list[Any] = []
    req = _Request(cfg, stream)
    try:
        async with httpx.AsyncClient(timeout=stream.timeout_seconds, transport=transport, follow_redirects=True) as client:
            auth_headers, auth = await apply_auth(client, cfg.auth, req.base_url, cfg.retry, stats, sleep, scopes=cfg.scopes)
            headers = {**req.headers, **auth_headers}
            base_params = render_params(stream.params, template_context(last_sync))
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
                if resp.status_code == 401 and isinstance(cfg.auth, AuthOAuth2) and not refreshed:
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


async def fetch_sample(cfg: IntegrationConfig, stream_index: int = 0, transport: httpx.AsyncBaseTransport | None = None) -> tuple[Any, bool]:
    """Fetch only the first page of one stream. Returns (raw JSON body, has a Link rel="next" header)."""
    stream = cfg.streams[stream_index]
    stats = Stats()
    req = _Request(cfg, stream)
    try:
        async with httpx.AsyncClient(timeout=stream.timeout_seconds, transport=transport, follow_redirects=True) as client:
            auth_headers, auth = await apply_auth(client, cfg.auth, req.base_url, cfg.retry, stats, scopes=cfg.scopes)
            params = page_params(stream.pagination, render_params(stream.params, template_context(None)), 0, None)
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
def _skip_reason(stream: Stream, unavailable: set[str]) -> str | None:
    missing = [v for v in stream.requires_env if not lookup_ref(v)]
    if missing:
        return f"skipped: {', '.join(missing)} not set"
    if stream.fallback_for and stream.fallback_for not in unavailable:
        return f"skipped: {stream.fallback_for} is available"
    return None


def _is_fallback_target(cfg: IntegrationConfig, stream: Stream) -> bool:
    return any(s.fallback_for == stream.name for s in cfg.streams)


async def run_integration(cfg: IntegrationConfig, db: Any, on_new_event: OnNewEvent | None = None,
                          transport: httpx.AsyncBaseTransport | None = None, sleep: Sleep = asyncio.sleep) -> dict[str, Any]:
    """Fetch every stream, normalise, quarantine bad records, store (deduplicated) and trigger actions for new events.
    Never raises: errors go to the run record and the health page."""
    run_id = db.start_run(cfg.name)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = Stats()
    history = db.baseline_counts(cfg.name, cfg.exfiltration_guard.baseline_runs)  # before this run is recorded
    streams: list[dict[str, Any]] = []
    errors: list[str] = []
    unavailable: set[str] = set()
    fetched = new = quarantined = 0
    fatal = False
    for stream in cfg.streams:
        result: dict[str, Any] = {"name": stream.name, "entity": stream.entity, "fetched": 0, "new": 0, "updated": 0, "quarantined": 0}
        streams.append(result)
        if fatal:
            result["status"] = "not run"
            continue
        if reason := _skip_reason(stream, unavailable):
            result["status"] = reason
            continue
        try:
            pages_before = stats.pages
            records, _ = await fetch_records(cfg, stream, db.get_last_sync(f"{cfg.name}:{stream.name}"), transport, sleep=sleep, stats=stats)
            result["pages"] = stats.pages - pages_before
        except HTTPStatusError as exc:
            if exc.status in (403, 404) and _is_fallback_target(cfg, stream):
                unavailable.add(stream.name)
                result["status"] = f"not available (HTTP {exc.status}), using fallback"
                continue
            result["status"] = "error"
            errors.append(f"{stream.name}: {mask_text(str(exc))}")
            fatal = isinstance(exc, AuthError)  # every other stream would fail the same way
            continue
        except (TransientError, NotConfiguredError) as exc:
            result["status"] = "error"
            errors.append(f"{stream.name}: {mask_text(str(exc))}")
            fatal = True
            continue
        except EngineError as exc:
            result["status"] = "error"
            errors.append(f"{stream.name}: {mask_text(str(exc))}")
            continue
        except Exception as exc:  # unexpected bug: record it instead of crashing the scheduler
            log.exception("integration %s stream %s crashed", cfg.name, stream.name)
            result["status"] = "error"
            errors.append(f"{stream.name}: Unexpected error: {mask_text(f'{type(exc).__name__}: {exc}')}")
            continue
        for record in records:
            try:
                row = normalise(record, stream, cfg.name, started)
            except BadRecord as exc:  # bad data never stops the run: park it with the reason
                db.quarantine(cfg.name, run_id, record, str(exc), stream.name, stream.entity)
                result["quarantined"] += 1
                continue
            outcome = db.store(row)
            if outcome in ("new", "updated"):
                result[outcome] += 1
            if outcome == "new" and stream.entity == "event" and on_new_event:
                try:
                    await on_new_event(row)
                except Exception:  # an action failure must never fail ingestion
                    log.exception("action handling failed for %s/%s", row["source"], row["id"])
        result["fetched"] = len(records)
        result["status"] = "ok"
        if result["quarantined"]:
            result["note"] = f"{result['quarantined']} of {len(records)} invalid (quarantined)"
        db.set_last_sync(f"{cfg.name}:{stream.name}", started)
        fetched += len(records)
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
    detail = {"streams": streams, "retry_log": stats.retry_log[-20:]}
    if suspicious:
        detail["guard"] = suspicious
    db.finish_run(run_id, status, fetched, new, stats.pages, stats.retries, error, quarantined, detail)
    return {"status": status, "error": error, "records_fetched": fetched, "records_new": new, "pages": stats.pages,
            "retries": stats.retries, "quarantined": quarantined, "suspicious": suspicious, "streams": streams,
            "retry_log": stats.retry_log}


async def dry_run_integration(cfg: IntegrationConfig, sample_size: int = 5, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """Run every stream once WITHOUT saving: first `sample_size` raw + normalised records per stream."""
    streams: list[dict[str, Any]] = []
    unavailable: set[str] = set()
    errors: list[str] = []
    for stream in cfg.streams:
        if reason := _skip_reason(stream, unavailable):
            streams.append({"name": stream.name, "entity": stream.entity, "status": reason})
            continue
        try:
            records, stats = await fetch_records(cfg, stream, None, transport=transport, record_limit=sample_size)
        except HTTPStatusError as exc:
            if exc.status in (403, 404) and _is_fallback_target(cfg, stream):
                unavailable.add(stream.name)
                streams.append({"name": stream.name, "entity": stream.entity, "status": f"not available (HTTP {exc.status})"})
                continue
            errors.append(f"{stream.name}: {exc}")
            continue
        except EngineError as exc:
            errors.append(f"{stream.name}: {exc}")
            continue
        raw, normalised, bad = [], [], []
        for r in records[:sample_size]:
            try:
                row = normalise(r, stream, cfg.name)
            except BadRecord as exc:
                bad.append({"raw": r, "reason": str(exc)})
                continue
            row.pop("raw")
            raw.append(r)
            normalised.append(row)
        streams.append({"name": stream.name, "entity": stream.entity, "status": "ok", "raw": raw, "normalised": normalised,
                        "quarantined": bad, "pages": stats.pages, "retries": stats.retries, "retry_log": stats.retry_log})
    ok = [s for s in streams if s.get("status") == "ok"]
    if not ok:
        return {"ok": False, "stage": "fetch", "errors": errors or ["No stream could run (check requires_env / fallback settings)"],
                "streams": streams}
    first = ok[0]
    return {"ok": True, "errors": errors, "streams": streams, "raw": first["raw"], "normalised": first["normalised"],
            "quarantined": first["quarantined"], "pages": first["pages"], "retries": first["retries"], "retry_log": first["retry_log"]}
