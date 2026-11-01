# Architecture and project layout

How one engine runs every config, and where the code lives.

[← Back to the docs index](README.md)

## Architecture

```
  configs/integrations/*.yaml  ── validated (pydantic, B-2) ──►  scheduler.Registry (APScheduler, hot reload, FR-4)
  (base_url, auth, headers, retry, rate_limit, streams[])                     │ every schedule_seconds / Run now
                                                                              ▼
  ┌──────────────────────────────────────── engine.run_integration (ONE engine) ────────────────────────────────┐
  │ for each stream (parents before for_each children; fan-out = N items, `concurrency` at a time):            │
  │                   auth (FR-1) ─► request (FR-2) ─► paginate (FR-3) ─► send_with_retry (FR-7 1s/2s/4s,        │
  │                   ${NAME} ─► vault/env (FR-6)       page/offset/       FR-8 Retry-After / reset headers /     │
  │                                                     cursor/link        pacing / slow-down)                    │
  │                   ─► records_path ─► normalise per entity (FR-5) ─► BadRecord? ─► quarantine (FR-9) ─► store   │
  │ after the run: exfiltration guard (rolling baseline)  ·  B-4 failure streak ─► Slack / email / banner         │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────────┘
                                                  ▼
       SQLite (one store, FR-11):  users | devices | events | repositories  (UNIQUE source+id, + source, fetched_at)
                                   runs · quarantine · sync_state (B-1) · secrets (Fernet ciphertext) · alerts
                                                  ▼
       FastAPI /api/* (sign-in + roles, audit) ──►  UI: Overview · Events · Users · Devices · Repositories · Integrations (FR-10)
                                                     · Add integration (B-5) · Actions & tickets · Audit log
                       ──►  actions: Jira ticket for incidents (real Jira, project KAN) · Slack on repeated failure (B-4)

  Real APIs: GitHub · Okta · Jira Cloud · NVD · Tailscale · CISA KEV     Test doubles only (tests/fakes, never started by the platform)
```


## Project layout

```
integration_platform/  config.py (models, validation, ${NAME} resolution) · engine.py (auth, paging, retries, rate limits, runs)
                       normaliser.py (common schema, quarantine rules) · db.py (users/devices/events, runs, audit, vault rows)
                       auth.py (sign-in, roles, sessions) · vault.py · logmask.py · alerts.py (B-4) · actions.py · scheduler.py
                       ai_mapper.py · demo.py · api.py · static/ (app, home page and docs: plain HTML/CSS/JS, no build step, offline)
configs/integrations/  github, okta, jira, nvd, tailscale (real) · cisa_kev (added live)
configs/actions/       create_jira_ticket.yaml (real Jira, project KAN) · slack_failure_alert.yaml (B-4)
configs/examples/      cisa_kev.yaml (what the live demo creates)
tests/                 295 tests, incl. test_access.py (roles, audit), test_public.py (public pages, sign-in) and test_git_hygiene.py
tests/fakes/           in-process fake tools for the tests (CloudTrail, Firewall, OAuth2 Okta, Jira) + their configs and kev.json
```
