"""Mock Firewall (port 9002).

Auth: API key in header X-API-Key (MOCK_FIREWALL_API_KEY).
Pagination: page number. GET /logs?page=&page_size= -> {"results":[...], "page":1, "total_pages":3}
Device inventory: GET /devices?page=&page_size= (same paging) - every device field: mac, hostname, ipv4_address,
os_name/os_version, user (owner), last_seen (epoch seconds).
Rate limiting: ~1 in 5 requests returns HTTP 429 when random faults are on (FIREWALL_RATE_LIMIT, default off with DEMO_MODE=on).
Demo controls: POST /__demo/rate-limit-next?count=2 makes exactly the next 2 requests return 429.
"""
from __future__ import annotations

import hashlib
import random
import time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tests.fakes.common import (
    HOSTNAMES, MALFORMED_KINDS, USERS, add_demo_controls, any_ip, check_header_key, env, faults_on, inject_malformed, private_ip, recent_time,
    sprinkle_malformed,
)

TOTAL_PAGES = 3
MESSAGES = {
    "LOW": ["Geo-blocked connection dropped", "ICMP sweep dropped", "Policy deny: outbound SMB"],
    "MEDIUM": ["Port scan blocked", "DNS tunnelling suspected", "Inbound Telnet attempt blocked"],
    "HIGH": ["Brute force login blocked (RDP)", "SQL injection attempt blocked", "Brute force login blocked (SSH)"],
    "CRITICAL": ["Outbound connection to known C2 server", "Exploit attempt: CVE-2024-3400 blocked", "Data exfiltration volume threshold exceeded"],
}

app = FastAPI(title="Mock Firewall")
controls = add_demo_controls(app)
_next_id = int(time.time()) % 1_000_000 * 100  # int ids, unique across restarts in practice


def _log() -> dict:
    global _next_id
    _next_id += 1
    level = random.choices(list(MESSAGES), weights=[42, 36, 15, 7])[0]
    return {
        "id": _next_id,
        "level": level,
        "msg": random.choice(MESSAGES[level]),
        "src": any_ip(),
        "dst": private_ip(),
        "dst_port": random.choice([22, 80, 443, 445, 3389, 53, 1433]),
        "action": "blocked",
        "ts": int(recent_time().timestamp()),
    }


def malform(rec: dict, kind: str | None = None) -> dict:
    """A realistic broken record: missing id, garbage timestamp, or a list where one IP belongs."""
    rec = dict(rec)
    kind = kind or random.choice(MALFORMED_KINDS)
    if kind == "missing_id":
        rec.pop("id", None)
    elif kind == "bad_time":
        rec["ts"] = "N/A"
    else:
        rec["src"] = [rec["src"], "10.0.0.1"]
    return rec


@app.get("/logs")
def logs(request: Request, page: int = 1, page_size: int = 4):
    check_header_key(request, "X-API-Key", _key())
    if controls.take_rate_limit():
        return JSONResponse({"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(controls.retry_after)})
    if faults_on("FIREWALL_RATE_LIMIT") and random.random() < 0.2:
        return JSONResponse({"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "1"})
    page_size = max(1, min(page_size, 50))
    results = sprinkle_malformed([_log() for _ in range(page_size)], malform) if 1 <= page <= TOTAL_PAGES else []
    results = inject_malformed(results, controls, malform, _log)
    return {"results": results, "page": page, "total_pages": TOTAL_PAGES}


def _key() -> str:
    return env("MOCK_FIREWALL_API_KEY", "fw-demo-key-2b8e41")


OSES = [("Windows", "11 23H2"), ("Windows Server", "2022"), ("macOS", "14.5"), ("Ubuntu", "22.04"), ("Windows", "10 22H2")]
DEVICE_COUNT = 15


def device(i: int) -> dict:
    """Stable device identity (so re-fetches update, not duplicate), fresh last_seen on every call."""
    host = HOSTNAMES[i % len(HOSTNAMES)]
    digest = hashlib.md5(host.encode()).hexdigest()
    os_name, os_version = OSES[int(digest[:2], 16) % len(OSES)]
    owner = USERS[int(digest[2:4], 16) % len(USERS)]
    return {
        "mac": ":".join(digest[j:j + 2] for j in range(0, 12, 2)),
        "hostname": host,
        "ipv4_address": f"10.{int(digest[4:6], 16) % 20}.{int(digest[6:8], 16)}.{int(digest[8:10], 16) % 250 + 2}",
        "os_name": os_name,
        "os_version": os_version,
        "user": f"{owner}@mitigata-demo.in",
        "last_seen": int(recent_time(window_s=3600).timestamp()),
        "is_online": random.random() < 0.8,
    }


def malform_device(rec: dict, kind: str | None = None) -> dict:
    rec = dict(rec)
    kind = kind or random.choice(MALFORMED_KINDS)
    if kind == "missing_id":
        rec.pop("mac", None)
    elif kind == "bad_time":
        rec["last_seen"] = "never"
    else:
        rec["hostname"] = {"name": rec["hostname"]}
    return rec


@app.get("/devices")
def devices(request: Request, page: int = 1, page_size: int = 5):
    check_header_key(request, "X-API-Key", _key())
    page_size = max(1, min(page_size, 50))
    total_pages = -(-DEVICE_COUNT // page_size)
    start = (page - 1) * page_size
    results = [device(i) for i in range(start, min(start + page_size, DEVICE_COUNT))] if page >= 1 else []
    results = sprinkle_malformed(results, malform_device)
    return {"results": results, "page": page, "total_pages": total_pages}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "mock_firewall"}


if __name__ == "__main__":
    uvicorn.run(app, host=env("BIND_HOST", "127.0.0.1"), port=int(env("MOCK_FIREWALL_PORT", "9002")), log_level="warning")
