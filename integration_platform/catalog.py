"""Integration catalog: research notes + templates for tools customers use (catalog/*.yaml).

Templates are NOT active integrations. "Use template" copies one into the wizard, where an admin fills in .env names,
tests it and saves it. Each tool's status is worked out here from the research notes and the engine's capabilities:

  connected           an active integration with the template's name exists
  template_ready      a validated template exists and the engine has everything it needs
  needs_verification  the engine could do it, but the events endpoint / flow is not confirmed in public docs
  needs_capability    the engine lacks something this API needs (the gap analysis counts these)
  no_public_api       no public API reference could be found
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from integration_platform.config import ROOT, ConfigError, validate_integration

CATALOG_DIR = ROOT / "catalog"

# What a tool's API can need from the engine. implemented=True once the engine supports it.
CAPABILITIES: dict[str, dict[str, Any]] = {
    "session_login": {"title": "Session-login token auth", "implemented": True,
                      "what": "Log in once (body, headers or Basic), read a token from the JSON or a response header, send it on every call."},
    "body_pagination": {"title": "Request-body pagination (incl. GraphQL cursors)", "implemented": False,
                        "what": "Put the page offset or cursor inside the JSON request body instead of the URL."},
    "id_lookup": {"title": "Two-step ID lookup", "implemented": False,
                  "what": "Call 1 lists record IDs, call 2 fetches the records for those IDs."},
    "push_receiver": {"title": "Syslog / webhook receiver", "implemented": False,
                      "what": "Accept events the tool pushes to us instead of pulling them."},
    "aws_sigv4": {"title": "AWS SigV4 request signing", "implemented": False, "what": "Sign every request with AWS Signature Version 4."},
    "service_account_jwt": {"title": "Service-account JWT (Google OAuth2)", "implemented": False,
                            "what": "Exchange a signed service-account JWT for an access token."},
    "xml_api": {"title": "XML request / response", "implemented": False, "what": "Send XML requests and parse XML responses."},
    "rpc_api": {"title": "RPC-style session API", "implemented": False, "what": "Call named RPC methods inside an authenticated session."},
    "export_acknowledge": {"title": "Export acknowledge (bookmark)", "implemented": False,
                           "what": "Acknowledge each exported chunk so the tool advances its bookmark."},
}
STATUS_ORDER = ["connected", "template_ready", "needs_verification", "needs_capability", "no_public_api"]
CATEGORIES = ["SIEM", "EDR", "DLP", "Firewall", "Cloud security"]


def load_entries(directory: Path | None = None) -> list[dict[str, Any]]:
    """Every catalog file as {"id", "catalog": {...}, "template": {...} | None, "template_error": str | None}."""
    out = []
    for path in sorted((directory or CATALOG_DIR).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        meta, template, error = data.get("catalog") or {}, data.get("template"), None
        if template:
            try:
                validate_integration(template)
            except ConfigError as exc:
                error = "; ".join(exc.errors)
        out.append({"id": path.stem, "catalog": meta, "template": template, "template_error": error})
    return out


def status_of(entry: dict[str, Any], active: set[str]) -> dict[str, Any]:
    meta = entry["catalog"]
    needs = meta.get("needs") or []
    missing = [n for n in needs if not CAPABILITIES.get(n, {}).get("implemented")]
    if str(meta.get("api_style", "")).startswith("none public"):
        return {"status": "no_public_api", "label": "No public API"}
    if missing:
        return {"status": "needs_capability", "label": f"Needs capability: {CAPABILITIES[missing[0]]['title']}", "missing": missing}
    if entry["template"] is None or entry["template_error"]:
        return {"status": "needs_verification", "label": "Needs verification", "reason": entry["template_error"] or meta.get("notes")}
    if entry["template"]["name"] in active:
        return {"status": "connected", "label": "Connected"}
    return {"status": "template_ready", "label": "Template ready"}


def catalog_view(active: set[str]) -> dict[str, Any]:
    """Entries with status, counts per status, and the gap table: what each missing capability would unlock."""
    entries = []
    for e in load_entries():
        entries.append({**e, **status_of(e, active), "uses": [n for n in (e["catalog"].get("needs") or []) if CAPABILITIES[n]["implemented"]]})
    counts = {s: sum(1 for e in entries if e["status"] == s) for s in STATUS_ORDER}
    gaps = []
    for key, cap in CAPABILITIES.items():
        tools = [e["catalog"]["name"] for e in entries if key in (e["catalog"].get("needs") or [])]
        if not tools:
            continue
        sole = [e["catalog"]["name"] for e in entries if (e.get("missing") or [None])[0] == key and len(e.get("missing") or []) == 1]
        gaps.append({"capability": key, **cap, "tools": tools, "count": len(tools), "would_unlock": sole})
    gaps.sort(key=lambda g: (g["implemented"], -g["count"]))
    return {"entries": entries, "counts": counts, "gaps": gaps, "capabilities": CAPABILITIES, "categories": CATEGORIES}
