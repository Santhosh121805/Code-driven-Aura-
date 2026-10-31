"""MOCK Lacework FortiCNAPP (tests only). Follows the documented token flow (POST /api/v2/access/tokens with the secret
in X-LW-UAKS and keyId in the JSON body, response {token, expiresAt}; Fortinet API reference) and the Alerts shape
seen in integration docs (GET /api/v2/Alerts with startTime/endTime, data[], paging.urls.nextPage). Values are invented."""
from __future__ import annotations

import itertools

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request

SECRET, KEY_ID = "lw-secret-not-real", "LW_KEY_TEST"
app = FastAPI(title="Mock Lacework")
_tokens = itertools.count(1)
state = {"valid": set(), "logins": 0, "queries": []}

ALERTS = [
    {"alertId": 101, "startTime": "2026-10-31T09:00:00.000Z", "alertType": "NewViolations", "alertName": "Root account used", "severity": "High"},
    {"alertId": 102, "startTime": "2026-10-31T09:20:00.000Z", "alertType": "CloudActivityLogIngestionFailed", "alertName": "CloudTrail ingestion failed", "severity": "Medium"},
    {"alertId": 103, "startTime": "2026-10-31T09:40:00.000Z", "alertType": "PotentiallyCompromisedHost", "alertName": "Known bad IP contacted", "severity": "Critical"},
]


def reset() -> None:
    state.update(valid=set(), logins=0, queries=[])


@app.post("/api/v2/access/tokens", status_code=201)
def access_tokens(body: dict = Body(...), x_lw_uaks: str | None = Header(None)) -> dict:
    state["logins"] += 1
    if x_lw_uaks != SECRET or body.get("keyId") != KEY_ID:
        raise HTTPException(401, "Invalid key")
    token = f"lw-session-{next(_tokens)}-0f0f"
    state["valid"] = {token}
    return {"token": token, "expiresAt": "2026-10-31T11:00:00.000Z"}


def _check(authorization: str | None) -> None:
    if not authorization or authorization.removeprefix("Bearer ") not in state["valid"]:
        raise HTTPException(401, "Token expired or invalid")


@app.get("/api/v2/Alerts")
def alerts(request: Request, startTime: str = Query(...), endTime: str = Query(...), authorization: str | None = Header(None)) -> dict:  # noqa: N803
    _check(authorization)
    state["queries"].append((startTime, endTime))
    next_page = str(request.base_url).rstrip("/") + "/api/v2/Alerts/page-2-abc"
    return {"paging": {"rows": 2, "totalRows": 3, "urls": {"nextPage": next_page}}, "data": ALERTS[:2]}


@app.get("/api/v2/Alerts/page-2-abc")
def alerts_page_2(authorization: str | None = Header(None)) -> dict:
    _check(authorization)
    return {"paging": {"rows": 1, "totalRows": 3, "urls": {"nextPage": None}}, "data": ALERTS[2:]}
