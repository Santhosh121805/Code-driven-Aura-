"""FR-7 / FR-8: identical reliability for every connector.
Timeouts, network errors, 5xx -> retries at exactly 1s, 2s, 4s then FAILED. 401/403 -> never retried.
429 -> Retry-After (seconds or HTTP date) > configurable reset header > exponential backoff. Proactive slow-down."""
import time
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from integration_platform.engine import AuthError, TransientError, fetch_records, run_integration
from tests.conftest import SleepRecorder, load, no_sleep, only

PAGE = {"results": [{"id": 1, "level": "HIGH", "msg": "Port scan blocked", "src": "10.0.0.5", "dst": "10.0.0.9", "ts": 1793426456}],
        "page": 1, "total_pages": 1}


def scripted(responses: list):
    """Transport returning the scripted responses in order (an Exception instance is raised; a dict is (status, body, headers))."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        item = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        if isinstance(item, Exception):
            raise item
        status, body, headers = (item + ({},))[:3] if len(item) == 2 else item
        return httpx.Response(status, json=body, headers=headers)
    return httpx.MockTransport(handler), calls


def fw():
    return only("acme_firewall", "logs")


async def fetch(cfg, transport, sleep):
    return await fetch_records(cfg, cfg.streams[0], transport=transport, sleep=sleep)


# ------------------------------------------------------------------ FR-7: transient failures
async def test_5xx_backoff_is_exactly_1_2_4_then_failed():
    transport, calls = scripted([(503, {})])
    sleep = SleepRecorder()
    with pytest.raises(TransientError, match=r"HTTP 503 .* FAILED after 3 retries \(waited 1s, 2s, 4s\)"):
        await fetch(fw(), transport, sleep)
    assert sleep.delays == [1, 2, 4] and calls["n"] == 4


async def test_timeouts_and_network_errors_are_retried_then_recover():
    transport, _ = scripted([httpx.ReadTimeout("slow"), httpx.ConnectError("network is unreachable"), (200, PAGE)])
    sleep = SleepRecorder()
    records, stats = await fetch(fw(), transport, sleep)
    assert len(records) == 1 and stats.retries == 2 and sleep.delays == [1, 2]


async def test_network_off_mid_run_fails_after_1_2_4_and_records_it(db):
    """Page 1 works, then the network drops: retries 1s/2s/4s, then the run is marked failed with a clear error."""
    page1 = {"results": [{"id": 1, "level": "LOW", "msg": "x", "src": "10.0.0.1", "dst": "10.0.0.2", "ts": 1793426456}], "page": 1, "total_pages": 3}
    transport, _ = scripted([(200, page1), httpx.ConnectError("[Errno 101] Network is unreachable")])
    sleep = SleepRecorder()
    result = await run_integration(fw(), db, transport=transport, sleep=sleep)
    assert sleep.delays == [1, 2, 4]
    assert result["status"] == "error" and result["retries"] == 3
    assert "connection failed (network down or host unreachable)" in result["error"] and "FAILED after 3 retries" in result["error"]
    assert db.recent_runs("acme_firewall")[0]["status"] == "error"


async def test_unroutable_host_really_fails_after_retries():
    """A real socket to a non-listening port: genuine connection errors, same 1/2/4s schedule."""
    cfg = only("acme_firewall", "logs").model_copy(update={"base_url": "http://127.0.0.1:9"})
    sleep = SleepRecorder()
    with pytest.raises(TransientError, match="connection failed"):
        await fetch(cfg, None, sleep)
    assert sleep.delays == [1, 2, 4]


# ------------------------------------------------------------------ auth errors
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_errors_are_never_retried(status):
    transport, calls = scripted([(status, {"message": "Bad credentials"})])
    sleep = SleepRecorder()
    with pytest.raises(AuthError, match=f"Authentication failed: HTTP {status}"):
        await fetch(fw(), transport, sleep)
    assert calls["n"] == 1 and sleep.delays == []


# ------------------------------------------------------------------ FR-8: rate limits
async def test_429_honours_retry_after_seconds():
    transport, _ = scripted([(429, {}, {"Retry-After": "5"}), (200, PAGE)])
    sleep = SleepRecorder()
    records, stats = await fetch(fw(), transport, sleep)
    assert len(records) == 1 and sleep.delays == [5]
    assert "HTTP 429: waited 5s due to Retry-After" in stats.retry_log


async def test_429_honours_retry_after_http_date():
    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    transport, _ = scripted([(429, {}, {"Retry-After": when}), (200, PAGE)])
    sleep = SleepRecorder()
    await fetch(fw(), transport, sleep)
    assert 27 <= sleep.delays[0] <= 31


async def test_429_without_retry_after_uses_configured_reset_header():
    reset = int(time.time()) + 20
    cfg = fw().model_copy(update={"rate_limit": fw().rate_limit.model_copy(update={"reset_header": "x-ratelimit-reset"})})
    transport, _ = scripted([(429, {}, {"x-ratelimit-reset": str(reset)}), (200, PAGE)])
    sleep = SleepRecorder()
    _, stats = await fetch(cfg, transport, sleep)
    assert 19 <= sleep.delays[0] <= 22 and "due to x-ratelimit-reset" in stats.retry_log[0]


async def test_429_without_any_hint_falls_back_to_exponential_backoff():
    transport, _ = scripted([(429, {}), (429, {}), (200, PAGE)])
    sleep = SleepRecorder()
    _, stats = await fetch(fw(), transport, sleep)
    assert sleep.delays == [1, 2] and "exponential backoff" in stats.retry_log[0]


async def test_429_waits_are_capped():
    cfg = fw().model_copy(update={"rate_limit": fw().rate_limit.model_copy(update={"max_wait_seconds": 10})})
    transport, _ = scripted([(429, {}, {"Retry-After": "3600"}), (200, PAGE)])
    sleep = SleepRecorder()
    await fetch(cfg, transport, sleep)
    assert sleep.delays == [10]


async def test_429_gives_up_after_max_waits():
    transport, calls = scripted([(429, {}, {"Retry-After": "1"})])
    with pytest.raises(Exception, match="HTTP 429 rate limited"):
        await fetch(fw(), transport, SleepRecorder())
    assert calls["n"] == 6  # 1 + max_429_retries (5)


async def test_proactive_slowdown_when_remaining_is_near_zero():
    """GitHub-style headers: remaining=0 -> the NEXT call waits until reset (no wasted wait after the last page)."""
    reset = int(time.time()) + 15
    pages = [
        (200, {"results": [{"id": 1}], "page": 1, "total_pages": 2}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)}),
        (200, {"results": [{"id": 2}], "page": 2, "total_pages": 2}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)}),
    ]
    cfg = fw().model_copy(update={"rate_limit": fw().rate_limit.model_copy(update={"reset_header": "x-ratelimit-reset",
                                                                                     "remaining_header": "x-ratelimit-remaining"})})
    transport, calls = scripted(pages)
    sleep = SleepRecorder()
    records, _ = await fetch(cfg, transport, sleep)
    assert len(records) == 2 and calls["n"] == 2
    assert len(sleep.delays) == 1 and 13 <= sleep.delays[0] <= 17  # waited once, before page 2 only


async def test_retried_run_is_recorded_with_retries(db):
    transport, _ = scripted([(429, {}, {"Retry-After": "1"}), (200, PAGE)])
    result = await run_integration(fw(), db, transport=transport, sleep=no_sleep)
    assert result["status"] == "success" and result["retries"] == 1
    assert db.recent_runs("acme_firewall")[0]["retries"] == 1
    assert "waited 1s due to Retry-After" in db.recent_runs("acme_firewall")[0]["detail"]["retry_log"][0]


async def test_mock_retry_after_demo_control(firewall):
    """The demo control returns 429 with Retry-After: 5 so the wait is visible on stage."""
    from fastapi.testclient import TestClient
    from tests.fakes import mock_firewall
    TestClient(mock_firewall.app).post("/__demo/rate-limit-next", params={"count": 1, "retry_after": 5})
    sleep = SleepRecorder()
    records, stats = await fetch(fw(), firewall, sleep)
    assert sleep.delays == [5] and "waited 5s due to Retry-After" in stats.retry_log[0] and len(records) == 12


async def test_min_interval_paces_requests():
    """NVD-style pacing: at least min_interval_seconds between calls (only between calls, not before the first)."""
    pages = [(200, {"results": [{"id": i}], "page": i, "total_pages": 3}) for i in (1, 2, 3)]
    cfg = fw().model_copy(update={"rate_limit": fw().rate_limit.model_copy(update={"min_interval_seconds": 6})})
    transport, calls = scripted(pages)
    sleep = SleepRecorder()
    records, _ = await fetch(cfg, transport, sleep)
    assert len(records) == 3 and len(sleep.delays) == 2 and all(5.5 <= d <= 6 for d in sleep.delays)


async def test_retry_after_zero_like_nvd_never_hammers():
    """Real NVD behaviour (keyless burst): HTTP 429 + Retry-After: 0. Wait at least the normal backoff instead."""
    transport, calls = scripted([(429, {}, {"Retry-After": "0"}), (429, {}, {"Retry-After": "0"}), (200, PAGE)])
    sleep = SleepRecorder()
    _, stats = await fetch(fw(), transport, sleep)
    assert sleep.delays == [1, 2] and calls["n"] == 3
    assert stats.retry_log[0] == "HTTP 429: waited 1s due to exponential backoff (Retry-After said 0s)"


async def test_retry_after_zero_with_known_window_waits_the_window():
    """NVD config: fallback_wait_seconds 30 -> one 30 s wait, then success (no hammering inside the rolling window)."""
    cfg = fw().model_copy(update={"rate_limit": fw().rate_limit.model_copy(update={"fallback_wait_seconds": 30})})
    transport, calls = scripted([(429, {}, {"Retry-After": "0"}), (200, PAGE)])
    sleep = SleepRecorder()
    _, stats = await fetch(cfg, transport, sleep)
    assert sleep.delays == [30] and calls["n"] == 2
    assert stats.retry_log[0] == "HTTP 429: waited 30s due to the rate-limit window (Retry-After said 0s)"
