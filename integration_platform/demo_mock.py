"""Demo source (Mock): a tiny fake security tool served by the platform itself at /mock/events.

It exists only so the demo controls can show behaviour real APIs cannot be told to produce on cue:
a 429 with Retry-After, a malformed record, and a stolen-token bulk export. The integration that reads it
(configs/integrations/demo_mock.yaml) is disabled, never scheduled, and runs only when a demo control fires.
Its data is labelled "Mock" everywhere; normal events never go above medium severity, so only the
exfiltration guard's critical alert can open a ticket.
"""
from __future__ import annotations

import hashlib
import itertools
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

NAME = "demo_mock"
PAGE_SIZE, PAGES = 4, 3  # 12 events per normal run

router = APIRouter(prefix="/mock", include_in_schema=False)
_lock = threading.Lock()
_ids = itertools.count(1)
_faults: dict[str, Any] = {}

TYPES = [("user.login.failed", "medium", "Failed sign-in for {u}"), ("policy.changed", "low", "Policy updated by {u}"),
         ("user.login", "info", "Sign-in by {u}"), ("file.shared.external", "medium", "File shared outside the company by {u}")]
USERS = ["a.chen@example.com", "j.rivera@example.com", "m.okafor@example.com", "s.patel@example.com"]


def reset() -> None:
    with _lock:
        _faults.clear()


def arm(kind: str, **detail: Any) -> None:
    """One-shot fault for the next request(s): rate_limit (count, retry_after), malformed, bulk (multiplier)."""
    with _lock:
        _faults[kind] = detail


def _take(kind: str) -> dict[str, Any] | None:
    with _lock:
        detail = _faults.get(kind)
        if detail is None:
            return None
        if kind == "rate_limit":
            detail["count"] -= 1
            if detail["count"] <= 0:
                _faults.pop(kind)
        else:
            _faults.pop(kind)
        return detail


def _event(n: int, now: datetime) -> dict[str, Any]:
    kind, severity, text = TYPES[n % len(TYPES)]
    user = USERS[n % len(USERS)]
    return {"event_id": f"mock-{n}", "time": (now - timedelta(seconds=n % 600)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "severity": severity, "event_type": kind, "message": text.format(u=user), "user": user,
            "src_ip": f"198.51.100.{n % 250 + 1}"}


@router.get("/events")
def events(page: int = Query(1, ge=1), page_size: int = Query(PAGE_SIZE, ge=1, le=500)) -> JSONResponse:
    rate = _take("rate_limit")
    if rate is not None:
        return JSONResponse({"error": "rate limited (mock)"}, status_code=429, headers={"Retry-After": str(rate["retry_after"])})
    now = datetime.now(timezone.utc)
    size = page_size
    bulk = _take("bulk") if page == 1 else None
    if bulk:
        size = page_size * bulk["multiplier"]  # what a stolen token doing a bulk export looks like
    records = [_event(next(_ids), now) for _ in range(size)]
    if page == 1 and _take("malformed") is not None:
        records[1]["time"] = "yesterday-ish"  # unparseable: quarantined, the rest of the run is stored
    return JSONResponse({"source": "Demo source (Mock)", "page": page, "total_pages": PAGES, "results": records})


HOSTNAMES = ["fin-laptop-01", "hr-laptop-07", "eng-ws-12", "eng-ws-19", "db-prod-02", "web-prod-01", "jump-host", "build-runner-3",
             "mkt-laptop-04", "ceo-macbook"]
OSES = [("Windows", "11 23H2"), ("Ubuntu", "22.04"), ("macOS", "14.5"), ("Windows Server", "2022")]


def _device(i: int, now: datetime) -> dict[str, Any]:
    """Stable identity per host (re-runs update, not duplicate); a fresh last_seen each time."""
    host = HOSTNAMES[i]
    digest = hashlib.md5(host.encode()).hexdigest()
    os_name, os_version = OSES[int(digest[:2], 16) % len(OSES)]
    return {"mac": ":".join(digest[j:j + 2] for j in range(0, 12, 2)), "hostname": host,
            "ipv4_address": f"10.20.{int(digest[2:4], 16)}.{int(digest[4:6], 16) % 250 + 2}", "os_name": os_name,
            "os_version": os_version, "user": USERS[i % len(USERS)],
            "last_seen": (now - timedelta(minutes=int(digest[6:8], 16) % 90)).strftime("%Y-%m-%dT%H:%M:%SZ")}


@router.get("/devices")
def devices() -> JSONResponse:
    now = datetime.now(timezone.utc)
    return JSONResponse({"source": "Demo source (Mock)", "results": [_device(i, now) for i in range(len(HOSTNAMES))]})
