"""Mock Jira Cloud (port 9004).

POST /rest/api/3/issue (Basic auth, Jira Cloud body shape) -> {"id": "...", "key": "SOC-<n>", "self": "..."}
GET  /                 -> auto-refreshing HTML list of tickets (newest first)
GET  /rest/api/3/issues -> JSON list of tickets (for scripts/tests)
POST /admin/reset      -> clears tickets (Basic auth), used by the platform's "Reset demo"
"""
from __future__ import annotations

import html
import threading
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from mocks.common import check_basic, env

app = FastAPI(title="Mock Jira")
_lock = threading.Lock()
_tickets: list[dict] = []
_counter = 0


def _auth(request: Request) -> None:
    check_basic(request, env("MOCK_JIRA_USER", "soc-bot@mitigata.local"), env("MOCK_JIRA_TOKEN", "jira-demo-token-91d2"))


@app.post("/rest/api/3/issue", status_code=201)
async def create_issue(request: Request) -> dict:
    global _counter
    _auth(request)
    try:
        body = await request.json()
        fields = body["fields"]
        project = fields["project"]["key"]
        summary = fields["summary"]
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be {'fields': {'project': {'key': ...}, 'summary': ...}}")
    with _lock:
        _counter += 1
        ticket = {
            "id": str(10000 + _counter),
            "key": f"{project}-{_counter}",
            "summary": summary,
            "description": fields.get("description", ""),
            "issuetype": (fields.get("issuetype") or {}).get("name", "Task"),
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        _tickets.append(ticket)
    return {"id": ticket["id"], "key": ticket["key"], "self": f"/rest/api/3/issue/{ticket['id']}"}


@app.get("/rest/api/3/issues")
def list_issues() -> list[dict]:
    with _lock:
        return list(reversed(_tickets))


@app.post("/admin/reset")
def reset(request: Request) -> dict:
    global _counter
    _auth(request)
    with _lock:
        _tickets.clear()
        _slack.clear()
        _counter = 0
    return {"status": "reset"}


# ---- mock Slack incoming webhook (offline stand-in for SLACK_WEBHOOK_URL), B-4 alerts land here
_slack: list[dict] = []


@app.post("/slack/webhook")
async def slack_webhook(request: Request) -> dict:
    body = await request.json()
    if not isinstance(body, dict) or not body.get("text"):
        raise HTTPException(status_code=400, detail="invalid_payload: expected {'text': ...}")
    with _lock:
        _slack.append({"text": body["text"], "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")})
    return {"ok": True}


@app.get("/slack/messages")
def slack_messages() -> list[dict]:
    with _lock:
        return list(reversed(_slack))


@app.get("/slack", response_class=HTMLResponse)
def slack_page() -> str:
    with _lock:
        msgs = list(reversed(_slack))
    items = "".join(f"<div class='msg'><span class='at'>{m['at']}</span><pre>{html.escape(m['text'])}</pre></div>" for m in msgs) \
        or "<p class='empty'>No alerts yet.</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3"><title>Mock Slack · #soc-alerts</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#1a1d21;color:#d1d2d3;margin:0}}
header{{background:#3f0e40;color:#fff;padding:14px 24px;font-weight:600}} main{{padding:16px 24px}}
.msg{{border-bottom:1px solid #2c2d30;padding:10px 0}} .at{{color:#9a9b9e;font-size:12px}} pre{{white-space:pre-wrap;margin:4px 0 0;font-family:inherit}}
.empty{{color:#9a9b9e}}</style></head><body><header># soc-alerts · Mock Slack ({len(msgs)})</header><main>{items}</main></body></html>"""


def _severity_class(summary: str) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if f"[{sev.upper()}]" in summary:
            return sev
    return "info"


@app.get("/", response_class=HTMLResponse)
def board() -> str:
    with _lock:
        tickets = list(reversed(_tickets))
    rows = "".join(
        f"<tr><td class='key'>{html.escape(t['key'])}</td>"
        f"<td><span class='sev {_severity_class(t['summary'])}'>{html.escape(t['issuetype'])}</span></td>"
        f"<td>{html.escape(t['summary'])}</td><td class='desc'>{html.escape(t['description'])}</td>"
        f"<td class='when'>{t['created']}</td></tr>"
        for t in tickets
    ) or "<tr><td colspan='5' class='empty'>No tickets yet. High/critical alerts will appear here automatically.</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3">
<title>Mock Jira · SOC board</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;color:#172b4d;margin:0}}
 header{{background:#0052cc;color:#fff;padding:14px 24px;font-size:18px;font-weight:600}}
 header small{{font-weight:400;opacity:.8;margin-left:10px}}
 main{{padding:20px 24px}} table{{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 2px rgba(9,30,66,.25)}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #ebecf0;font-size:14px;vertical-align:top}}
 th{{background:#fafbfc;color:#5e6c84;font-size:12px;text-transform:uppercase}}
 .key{{color:#0052cc;font-weight:600;white-space:nowrap}} .desc{{color:#5e6c84;font-size:12px}} .when{{white-space:nowrap;color:#5e6c84;font-size:12px}}
 .sev{{padding:2px 8px;border-radius:3px;font-size:12px;background:#dfe1e6}} .sev.critical{{background:#de350b;color:#fff}} .sev.high{{background:#ff8b00;color:#fff}}
 .empty{{text-align:center;color:#5e6c84;padding:30px}}
</style></head><body><header>Mock Jira · Project SOC<small>{len(tickets)} ticket(s) · auto-refresh 3s</small></header>
<main><table><tr><th>Key</th><th>Type</th><th>Summary</th><th>Description</th><th>Created</th></tr>{rows}</table></main></body></html>"""


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "mock_jira"}


if __name__ == "__main__":
    uvicorn.run(app, host=env("BIND_HOST", "127.0.0.1"), port=int(env("MOCK_JIRA_PORT", "9004")), log_level="warning")
