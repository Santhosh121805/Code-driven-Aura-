"""Mock Okta (OAuth2) (port 9003): System Log + Users, behind OAuth2 client credentials.

Auth: OAuth2 client credentials. POST /oauth2/v1/token (MOCK_OKTA_CLIENT_ID / MOCK_OKTA_CLIENT_SECRET) returns a bearer
      token; GET /api/v1/logs needs scope okta.logs.read, GET /api/v1/users needs okta.users.read.
Pagination: "next" link. The body is a top-level JSON list; the RFC 8288 Link header carries rel="next" until the last page.
Fields follow the Okta System Log: uuid, published, eventType, severity, actor.alternateId, client.ipAddress, displayMessage.
"""
from __future__ import annotations

import base64
import json
import random
import uuid
from datetime import timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mocks.common import (
    MALFORMED_KINDS, USERS, TokenIssuer, add_demo_controls, add_token_endpoint, any_ip, env, inject_malformed, recent_time,
    sprinkle_malformed,
)

TOTAL_EVENTS = 24
# (eventType, severity, displayMessage, outcome, weight)
CATALOG = [
    ("user.session.start", "INFO", "User login to Okta", "SUCCESS", 30),
    ("user.authentication.auth_via_mfa", "INFO", "Authentication of user via MFA", "SUCCESS", 15),
    ("policy.evaluate_sign_on", "INFO", "Evaluation of sign-on policy", "ALLOW", 10),
    ("user.session.start", "WARN", "User login to Okta", "FAILURE", 15),
    ("user.account.lock", "WARN", "Max sign in attempts exceeded", "FAILURE", 7),
    ("system.api_token.create", "WARN", "Create API token", "SUCCESS", 5),
    ("security.threat.detected", "ERROR", "Request from suspicious actor", "DENY", 6),
    ("user.mfa.factor.reset_all", "ERROR", "Reset all factors for user", "SUCCESS", 4),
    ("user.account.privilege.grant", "ERROR", "Grant user privilege", "SUCCESS", 4),
    ("user.session.impersonation.initiate", "ERROR", "Session impersonation initiated", "SUCCESS", 3),
]
CRITICAL = [c for c in CATALOG if c[1] == "ERROR"]
CITIES = ["Mumbai", "Bengaluru", "Hyderabad", "Chennai", "Pune", "New Delhi"]

app = FastAPI(title="Mock Okta (OAuth2)")
issuer = TokenIssuer(
    client_id=env("MOCK_OKTA_CLIENT_ID", "0oa-demo-client"),
    client_secret=env("MOCK_OKTA_CLIENT_SECRET", "okta-demo-secret-8c41"),
    allowed_scopes={"okta.logs.read", "okta.users.read", "okta.users.manage"},
)
add_token_endpoint(app, issuer, "/oauth2/v1/token")
controls = add_demo_controls(app)


def event(force_critical: bool = False) -> dict:
    etype, severity, message, outcome, _ = random.choice(CRITICAL) if force_critical else random.choices(CATALOG, weights=[c[4] for c in CATALOG])[0]
    user = random.choice(USERS)
    published = recent_time().astimezone(timezone.utc)
    return {
        "uuid": str(uuid.uuid4()),
        "published": published.strftime("%Y-%m-%dT%H:%M:%S.") + f"{published.microsecond // 1000:03d}Z",
        "eventType": etype,
        "version": "0",
        "severity": severity,
        "displayMessage": message,
        "actor": {"id": "00u" + uuid.uuid4().hex[:17], "type": "User",
                  "alternateId": f"{user}@mitigata-demo.in", "displayName": user.replace(".", " ").title()},
        "client": {"ipAddress": any_ip(), "geographicalContext": {"country": "India", "city": random.choice(CITIES)}},
        "outcome": {"result": outcome, "reason": "INVALID_CREDENTIALS" if outcome == "FAILURE" else None},
        "transaction": {"type": "WEB", "id": uuid.uuid4().hex[:20]},
    }


def malform(rec: dict, kind: str | None = None) -> dict:
    """A realistic broken record: missing uuid, garbage published time, or an object where the actor id belongs."""
    rec = json.loads(json.dumps(rec))
    kind = kind or random.choice(MALFORMED_KINDS)
    if kind == "missing_id":
        rec.pop("uuid", None)
    elif kind == "bad_time":
        rec["published"] = "yesterday 25:61"
    else:
        rec["actor"]["alternateId"] = {"id": rec["actor"]["id"]}
    return rec


def _cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _offset(after: str | None) -> int:
    try:
        return int(base64.urlsafe_b64decode(after.encode()).decode()) if after else 0
    except Exception:
        return 0


@app.get("/api/v1/logs")
def logs(request: Request, limit: int = 10, after: str | None = None) -> JSONResponse:
    issuer.check(request, "okta.logs.read")
    limit = max(1, min(limit, 100))
    offset = _offset(after)
    count = max(0, min(limit, TOTAL_EVENTS - offset))
    # Guarantee at least one critical (severity ERROR) event per page so the demo always shows a critical alert.
    body = sprinkle_malformed([event(force_critical=(i == 0)) for i in range(count)], malform, skip_first=True)
    body = inject_malformed(body, controls, malform, event)
    links = [f'<{request.url}>; rel="self"']
    if offset + count < TOTAL_EVENTS:
        links.append(f'<{request.url.include_query_params(limit=limit, after=_cursor(offset + count))}>; rel="next"')
    return JSONResponse(body, headers={"Link": ", ".join(links)})


USER_STATUSES = ["ACTIVE"] * 7 + ["SUSPENDED", "LOCKED_OUT", "PROVISIONED"]


def user(i: int) -> dict:
    """Okta user object: stable id/profile, lastLogin refreshed on every call."""
    login = USERS[i % len(USERS)]
    first, _, last = login.partition(".")
    status = USER_STATUSES[i % len(USER_STATUSES)]
    last_login = recent_time(window_s=86400 * 3).astimezone(timezone.utc)
    return {
        "id": "00u" + uuid.uuid5(uuid.NAMESPACE_DNS, login).hex[:17],
        "status": status,
        "created": "2024-04-01T09:00:00.000Z",
        "lastLogin": None if status == "PROVISIONED" else last_login.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "profile": {"firstName": first.title(), "lastName": last.title() or None, "email": f"{login}@mitigata-demo.in",
                    "login": f"{login}@mitigata-demo.in"},
    }


def malform_user(rec: dict, kind: str | None = None) -> dict:
    rec = json.loads(json.dumps(rec))
    kind = kind or random.choice(MALFORMED_KINDS)
    if kind == "missing_id":
        rec.pop("id", None)
    elif kind == "bad_time":
        rec["lastLogin"] = "last tuesday"
    else:
        rec["profile"]["email"] = [rec["profile"]["email"], "alias@mitigata-demo.in"]
    return rec


@app.get("/api/v1/users")
def users(request: Request, limit: int = 5, after: str | None = None) -> JSONResponse:
    issuer.check(request, "okta.users.read")
    limit = max(1, min(limit, 200))
    offset = _offset(after)
    body = sprinkle_malformed([user(i) for i in range(offset, min(offset + limit, len(USERS)))], malform_user)
    links = [f'<{request.url}>; rel="self"']
    if offset + limit < len(USERS):
        links.append(f'<{request.url.include_query_params(limit=limit, after=_cursor(offset + limit))}>; rel="next"')
    return JSONResponse(body, headers={"Link": ", ".join(links)})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "mock_okta"}


if __name__ == "__main__":
    uvicorn.run(app, host=env("BIND_HOST", "127.0.0.1"), port=int(env("MOCK_OKTA_PORT", "9003")), log_level="warning")
