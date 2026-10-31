"""MOCK FortiGate (tests only). Follows the FortiOS REST log API shape: GET /api/v2/log/memory/event/system with an
API token in "Authorization: Bearer", offset paging through start/rows, and a response carrying results, start, rows,
completed and total_lines (field names from Fortinet's admin guide and community responses; values are invented)."""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Query

TOKEN = "fgt-test-token-not-real"
app = FastAPI(title="Mock FortiGate")

LOGS = [
    ("2026-10-31", "10:15:02", "0100032001", "information", "Admin login successful", "Administrator admin logged in successfully", "admin", "10.0.0.5"),
    ("2026-10-31", "10:16:40", "0100032002", "alert", "Admin login failed", "Administrator admin login failed from https(203.0.113.9)", "admin", "203.0.113.9"),
    ("2026-10-31", "10:20:11", "0100032003", "notice", "Admin logout successful", "Administrator admin logged out", "admin", "10.0.0.5"),
    ("2026-10-31", "10:31:57", "0100044547", "warning", "Object attribute configured", "Edit firewall.policy 12", "netops", "10.0.0.8"),
    ("2026-10-31", "10:42:03", "0100032011", "critical", "Admin lockout", "Administrator admin locked out after failed logins", "admin", "203.0.113.9"),
    ("2026-10-31", "10:45:20", "0100020013", "error", "FortiGuard update failed", "FortiGuard antivirus update failed", None, None),
    ("2026-10-31", "10:50:00", "0100022921", "information", "Routing log", "Static route updated", "netops", "10.0.0.8"),
]


def record(i: int) -> dict:
    date, time, logid, level, logdesc, msg, user, srcip = LOGS[i]
    rec = {"date": date, "time": time, "eventtime": 1793448902000000000 + i * 1_000_000_000, "logid": logid, "type": "event",
           "subtype": "system", "level": level, "logdesc": logdesc, "msg": msg, "devname": "FGT-HQ"}
    if user:
        rec["user"] = user
    if srcip:
        rec["srcip"] = srcip
    return rec


DEVICES = [("00:1a:2b:3c:4d:01", "fin-laptop-01", "10.0.10.21", "Windows", "11", "priya"),
           ("00:1a:2b:3c:4d:02", "hr-desktop-02", "10.0.10.22", "Windows", "10", "arjun"),
           ("00:1a:2b:3c:4d:03", "build-srv-01", "10.0.20.5", "Linux", "Ubuntu 22.04", None)]


@app.get("/api/v2/monitor/user/device/query")
def device_query(authorization: str | None = Header(None)) -> dict:
    """Device inventory (FortiOS monitor API shape: results list with mac, hostname, ipv4_address, os_name, ...)."""
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "Unauthorized")
    results = [{"mac": mac, "hostname": host, "ipv4_address": ip, "os_name": os_name, "os_version": ver, "last_seen": 1793448902 + i,
                **({"user": user} if user else {})} for i, (mac, host, ip, os_name, ver, user) in enumerate(DEVICES)]
    return {"http_method": "GET", "results": results, "vdom": "root", "path": "user", "name": "device", "status": "success"}


@app.get("/api/v2/log/memory/event/system")
def event_system(start: int = Query(0, ge=0), rows: int = Query(400, ge=1, le=1000), authorization: str | None = Header(None)) -> dict:
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "Unauthorized")
    page = [record(i) for i in range(start, min(start + rows, len(LOGS)))]
    return {"http_method": "GET", "results": page, "vdom": "root", "path": "log", "name": "system", "status": "success",
            "start": start, "rows": len(page), "completed": 100, "total_lines": len(LOGS)}
