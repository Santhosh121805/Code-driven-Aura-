"""Shared helpers for the mock security tools: realistic random data + auth checks."""
from __future__ import annotations

import base64
import os
import random
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import Form, HTTPException, Request

HOSTNAMES = [
    "finance-pc-07", "finance-pc-11", "hr-laptop-12", "dc-01", "dc-02", "web-srv-03",
    "dev-mbp-21", "payroll-db-02", "mail-gw-01", "sales-laptop-33", "it-admin-ws-04",
    "jump-host-01", "vpn-gw-02", "file-srv-05", "ceo-laptop-01",
]
USERS = [
    "priya.sharma", "arjun.mehta", "kavya.iyer", "rahul.verma", "ananya.rao",
    "vikram.singh", "sneha.nair", "rohan.gupta", "it.admin", "svc.backup",
]
EXTERNAL_IPS = ["185.220.101.42", "45.155.205.233", "103.75.190.11", "91.240.118.172", "194.26.29.15"]


def private_ip() -> str:
    """Random RFC1918 address."""
    choice = random.random()
    if choice < 0.5:
        return f"10.{random.randint(0, 20)}.{random.randint(0, 255)}.{random.randint(2, 254)}"
    if choice < 0.8:
        return f"192.168.{random.randint(0, 10)}.{random.randint(2, 254)}"
    return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(2, 254)}"


def any_ip() -> str:
    return random.choice(EXTERNAL_IPS) if random.random() < 0.35 else private_ip()


def recent_time(since: str | None = None, window_s: int = 120) -> datetime:
    """A timestamp in the last `window_s` seconds, but never before `since` (ISO)."""
    now = datetime.now(timezone.utc)
    floor = now - timedelta(seconds=window_s)
    if since:
        try:
            parsed = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            floor = max(floor, min(parsed, now))
        except ValueError:
            pass  # bad `since` -> ignore, like most real APIs
    span = max((now - floor).total_seconds(), 1)
    return now - timedelta(seconds=random.uniform(0, span))


def new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(6)}"


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


MALFORMED_RATE = 1 / 15
MALFORMED_KINDS = ("missing_id", "bad_time", "wrong_type")


def faults_on(var: str) -> bool:
    """Random faults (429s, malformed records): explicit VAR=on/off wins, else ON unless DEMO_MODE=on."""
    explicit = os.environ.get(var, "").strip().lower()
    if explicit in ("on", "off"):
        return explicit == "on"
    return os.environ.get("DEMO_MODE", "off").strip().lower() != "on"


class DemoControls:
    """Deterministic one-shot faults armed by the platform's "Demo controls" panel (POST /__demo/...)."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.rate_limit_next = 0           # number of upcoming requests to answer with HTTP 429
        self.retry_after = 1               # Retry-After seconds sent with those 429s
        self.malformed_next: list[str] = []  # malformed record kinds to inject into the next response(s)
        self.bulk_next = 0                 # multiplier for the next page (simulated stolen-token bulk export)

    def take_rate_limit(self) -> bool:
        if self.rate_limit_next > 0:
            self.rate_limit_next -= 1
            return True
        return False

    def take_malformed(self) -> str | None:
        return self.malformed_next.pop(0) if self.malformed_next else None

    def take_bulk(self) -> int:
        multiplier, self.bulk_next = self.bulk_next, 0
        return multiplier

    def state(self) -> dict:
        return {"rate_limit_next": self.rate_limit_next, "retry_after": self.retry_after, "malformed_next": self.malformed_next,
                "bulk_next": self.bulk_next}


def add_demo_controls(app) -> DemoControls:
    """Mount /__demo/* control endpoints (mock-only test hooks; real tools obviously have none)."""
    controls = DemoControls()

    @app.post("/__demo/rate-limit-next")
    def arm_rate_limit(count: int = 2, retry_after: int = 1) -> dict:
        controls.rate_limit_next = max(0, min(count, 10))
        controls.retry_after = max(0, min(retry_after, 60))
        return controls.state()

    @app.post("/__demo/malformed-next")
    def arm_malformed(kind: str = "bad_time", count: int = 1) -> dict:
        if kind not in MALFORMED_KINDS:
            raise HTTPException(status_code=400, detail=f"kind must be one of {MALFORMED_KINDS}")
        controls.malformed_next = [kind] * max(1, min(count, 10))
        return controls.state()

    @app.post("/__demo/bulk-export-next")
    def arm_bulk(multiplier: int = 20) -> dict:
        controls.bulk_next = max(2, min(multiplier, 100))
        return controls.state()

    @app.post("/__demo/reset")
    def reset_controls() -> dict:
        controls.reset()
        return controls.state()

    @app.get("/__demo/state")
    def get_state() -> dict:
        return controls.state()

    return controls


def inject_malformed(records: list[dict], controls: DemoControls, malform, fresh, position: int = 1) -> list[dict]:
    """If a malformed record is armed, insert exactly one (built from a fresh record, so its id is unique)."""
    kind = controls.take_malformed()
    if kind:
        records.insert(min(position, len(records)), malform(fresh(), kind))
    return records


def sprinkle_malformed(records: list[dict], malform, skip_first: bool = False) -> list[dict]:
    """Replace roughly 1 in 15 records with a malformed copy (when MALFORMED_RECORDS faults are on)."""
    if faults_on("MALFORMED_RECORDS"):
        for i, rec in enumerate(records):
            if (i > 0 or not skip_first) and random.random() < MALFORMED_RATE:
                records[i] = malform(rec)
    return records


def unauthorized(detail: str = "Unauthorized") -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


def check_bearer(request: Request, expected: str) -> None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer ") or not secrets.compare_digest(header[7:], expected):
        raise unauthorized("Missing or invalid bearer token")


def check_header_key(request: Request, header_name: str, expected: str) -> None:
    if not secrets.compare_digest(request.headers.get(header_name, ""), expected):
        raise unauthorized(f"Missing or invalid {header_name}")


class TokenIssuer:
    """Minimal OAuth2 client-credentials server (shared by mocks): issues random bearer tokens carrying scopes."""

    def __init__(self, client_id: str, client_secret: str, allowed_scopes: set[str], ttl: int = 3600):
        self.client_id, self.client_secret = client_id, client_secret
        self.allowed_scopes, self.ttl = allowed_scopes, ttl
        self._tokens: dict[str, tuple[set[str], float]] = {}

    def issue(self, grant_type: str, client_id: str, client_secret: str, scope: str) -> dict:
        ok = secrets.compare_digest(client_id, self.client_id) and secrets.compare_digest(client_secret, self.client_secret)
        if grant_type != "client_credentials" or not ok:
            raise unauthorized("Invalid client credentials")
        requested = set(scope.split()) if scope else set()
        if requested - self.allowed_scopes:
            raise HTTPException(status_code=400, detail=f"invalid_scope: {' '.join(sorted(requested - self.allowed_scopes))}")
        token = secrets.token_urlsafe(32)
        self._tokens[token] = (requested, time.time() + self.ttl)
        return {"access_token": token, "token_type": "Bearer", "expires_in": self.ttl, "scope": " ".join(sorted(requested))}

    def check(self, request: Request, required_scope: str) -> None:
        header = request.headers.get("Authorization", "")
        entry = self._tokens.get(header[7:]) if header.startswith("Bearer ") else None
        if entry is None or entry[1] < time.time():
            raise unauthorized("Missing, unknown or expired access token")
        if required_scope not in entry[0]:
            raise HTTPException(status_code=403, detail=f"insufficient_scope: requires {required_scope}")


def add_token_endpoint(app, issuer: TokenIssuer, path: str) -> None:
    """Mount the OAuth2 client-credentials token endpoint on a mock app."""
    @app.post(path)
    def token(grant_type: str = Form(...), client_id: str = Form(""), client_secret: str = Form(""), scope: str = Form("")) -> dict:
        return issuer.issue(grant_type, client_id, client_secret, scope)


def check_basic(request: Request, user: str, password: str) -> None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        raise unauthorized("Missing basic auth")
    try:
        got_user, _, got_pass = base64.b64decode(header[6:]).decode().partition(":")
    except Exception:
        raise unauthorized("Malformed basic auth")
    if not (secrets.compare_digest(got_user, user) and secrets.compare_digest(got_pass, password)):
        raise unauthorized("Invalid username or password")
