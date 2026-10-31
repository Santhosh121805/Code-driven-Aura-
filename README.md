# PlugSec: a Config-Driven Generic Integration Platform

**Add a new security tool with a config file, not code.** One generic engine reads the config, logs in, pages through the API, retries and slows down when it must, quarantines bad records, and maps everything into **one common schema**: users, devices and events. The schema lives in a single store, with a health page and alerts on repeated failure.

It runs against **real free-tier APIs** (GitHub, Okta, Jira Cloud, NVD, CISA KEV) with no mock data. Sign-in with three roles (admin, analyst, viewer) and an audit log protect the dashboard.

## PRD traceability

| PRD line | Where it is implemented | How to see it in the demo |
|---|---|---|
| **Goal 1** Config, not code | `configs/integrations/*.yaml`, validated by `config.IntegrationConfig`; hot-loaded by `scheduler.Registry` | Demo step 2: CISA KEV added live from **Add integration**; no restart, no code |
| **Goal 2** One common format | `config.ENTITY_FIELDS` + `normaliser.normalise` -> `db.Database.store` | Demo step 1: **Overview**, **Events**, **Users** pages |
| **Goal 3** Safe secrets | `config.SecretRef`, `vault.Vault` (Fernet), `logmask.MaskingFilter`, `.gitignore` | Demo step 4 |
| **Goal 4** Reliable by default | `engine.send_with_retry` / `rate_limit_wait` / quarantine in `engine.run_integration`, the same for every connector | Demo step 3 |
| **Goal 5** Visible health | `api._health`, Integrations tab | Demo step 5 |
| **Goal 6** 3+ real sources | `configs/integrations/{github,okta,jira,nvd}.yaml`, plus CISA KEV added live | "Real sources" table below |
| **FR-1** Auth: API key + more | `config.AuthApiKey` (with `prefix`, `optional`), `AuthBasic`, `AuthBearer`, `AuthOAuth2`; `engine.apply_auth` | Integration cards show the login type: GitHub Bearer, Okta API key (`SSWS`), Jira Basic, NVD optional API key, KEV none (OAuth2 is covered by the tests) |
| **FR-2** Endpoints | `config.Stream.endpoint/method/params/headers`, `${VAR}` in URLs; `engine._Request`, `engine.render_params` | The card's drawer lists each stream (`users → user · Link header`) |
| **FR-3** Pagination (2+) | `config.Pagination{Page,Offset,Cursor,Link}`; `engine.page_params`, `engine.next_link`, stop rules in `engine.fetch_records` | GitHub/Okta Link header, Jira/NVD offset, Jira issues cursor (page numbers covered by the tests) |
| **FR-4** Schedule | `IntegrationConfig.schedule_seconds` (real sources: 900 = 15 min); `scheduler.Registry._schedule` (APScheduler) | Card line "Last run 2 min ago · next in 13 min"; **Run now** (analyst or admin) |
| **FR-5** Mapping | `Stream.mapping` (JMESPath: rename, nested paths, joins), `Stream.transforms` (`time_format`, `severity_map`); `normaliser.parse_time` / `map_severity` | Event drawer (normalised fields + Raw JSON); the wizard **Test** step shows raw and normalised side by side |
| **FR-6** Secrets by name | Configs hold only `${github_token}` etc.; `config.resolve_env` -> `vault.Vault.get` (encrypted) -> env | Demo step 4 |
| **FR-7** Retries 1s/2s/4s then failed | `engine.send_with_retry` + `engine.backoff_seconds` (`RetrySpec` default 3 x base 1s); 401/403 never retried (`engine.AuthError`) | Demo controls: **Network off mid-run**, **Call GitHub with a wrong key** |
| **FR-8** Rate limits | `engine.rate_limit_wait`: Retry-After (seconds or HTTP date) > reset header (`x-ratelimit-reset`, `x-rate-limit-reset`) > backoff; `engine._note_remaining` proactive slow-down; `min_interval_seconds` pacing; `fallback_wait_seconds` | Recorded real NVD 429 below; `tests/test_retry.py` covers Retry-After seconds / HTTP date / reset headers |
| **FR-9** Bad data | `normaliser.BadRecord` (missing required field / wrong type / unparseable time) -> `db.Database.quarantine`, per stream; the run continues | Recorded real KEV test below; the card shows "N records quarantined · View" when it happens |
| **FR-10** Health | `api._health`: status, last run, records pulled, per-entity counts, last error, retries, failure streak, "Not configured", "Authentication failed" | **Integrations** page and **Overview** |
| **FR-11** One store, common schema | `db.py`: `users`, `devices`, `events` tables, `UNIQUE(source, id)`; every row has `source` + `fetched_at` | `GET /api/users`, `/api/devices`, `/api/events` |
| **B-1** Incremental sync | `{{ last_sync }}` / `last_sync_dt` in params (`engine.template_context`), stored per stream (`db.set_last_sync`) | Okta `since`, NVD `lastModStartDate` |
| **B-2** Config validation | pydantic models + `config.friendly_errors`; `POST /api/integrations/validate`; checked per wizard step | Wizard: empty Basics / literal secret are blocked with clear messages |
| **B-3** Test connection | `engine.dry_run_integration`, `POST /api/integrations/test` (nothing saved) | Wizard **Test** step: raw vs normalised |
| **B-4** Alert on repeated failure | `alerts.FailureAlerter` -> action engine (`actions.ActionRunner.notify`, `configs/actions/slack_failure_alert.yaml`), optional SMTP, UI banner + log | Demo controls: **Fail 3 times, then recover** -> banner + log (+ Slack when `SLACK_WEBHOOK_URL` is set) |
| **B-5** Web form -> config | `static/app.js` **Add integration** wizard with a live YAML panel (two-way) and inline field errors | Add Integration tab |

## Real sources (Section 4): each differs in login type and paging style

| Source | Login type | Paging style | Streams -> entity | Config |
|---|---|---|---|---|
| **GitHub REST API** | Bearer (fine-grained PAT, read-only) | Link header, page numbers (`per_page=100`) | `me`, `collaborators`, `org_members` (if `GITHUB_ORG`) -> users; `dependabot_alerts` -> events, falling back to `repo_events` if Dependabot is unavailable | `github.yaml` |
| **Okta (Integrator Free)** | API token header `Authorization: SSWS …` | Link header with `after` cursor | `/api/v1/users` -> users; `/api/v1/logs` (incremental `since`) -> events | `okta.yaml` |
| **Jira Cloud (free)** | Basic (email + API token) | Offset `startAt` / `maxResults` (issues: `/search/jql` token paging) | `/rest/api/3/users/search` -> users; issues -> events | `jira.yaml` |
| **NVD CVE API 2.0** | Optional API key header `apiKey` | Offset `startIndex` / `resultsPerPage` / `totalResults` | CVEs -> events (severity from CVSS v3.1, falling back to v3.0, then v2) | `nvd.yaml` |
| **CISA KEV** | None | None | KEV -> events. **Added live in the demo** | `configs/examples/cisa_kev.yaml` |

No source produces a device inventory today, so **Devices** shows an empty state until a tool with a `devices` stream is added. Fake tools exist only as test doubles in `tests/fakes/`; the platform never loads or starts them.

Real sources run every 15 minutes, with read-only endpoints and scopes only. Missing settings never cause errors: the card says **"Not configured: set `github_token`, `GITHUB_OWNER` …"** and nothing runs.

**Connect the real sources:** fill these in `.env` (names only ever appear in configs):

```
github_token=   GITHUB_OWNER=   GITHUB_REPO=   (optional GITHUB_ORG=)
okta_token=     OKTA_DOMAIN=integrator-1234567.okta.com
jira_email=     jira_token=     JIRA_DOMAIN=yourteam.atlassian.net
nvd_api_key=    (optional)
```

Then click **Run now** on each card. High and critical incidents from Okta and GitHub open tickets in your Jira project `KAN` (`configs/actions/create_jira_ticket.yaml`); CVE feeds and Jira's own issues are never ticketed.

## Architecture

```
  configs/integrations/*.yaml  ── validated (pydantic, B-2) ──►  scheduler.Registry (APScheduler, hot reload, FR-4)
  (base_url, auth, headers, retry, rate_limit, streams[])                     │ every schedule_seconds / Run now
                                                                              ▼
  ┌──────────────────────────────────────── engine.run_integration (ONE engine) ────────────────────────────────┐
  │ for each stream:  auth (FR-1) ─► request (FR-2) ─► paginate (FR-3) ─► send_with_retry (FR-7 1s/2s/4s,        │
  │                   ${NAME} ─► vault/env (FR-6)       page/offset/       FR-8 Retry-After / reset headers /     │
  │                                                     cursor/link        pacing / slow-down)                    │
  │                   ─► records_path ─► normalise per entity (FR-5) ─► BadRecord? ─► quarantine (FR-9) ─► store   │
  │ after the run: exfiltration guard (rolling baseline)  ·  B-4 failure streak ─► Slack / email / banner         │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────────┘
                                                  ▼
       SQLite (one store, FR-11):  users | devices | events  (UNIQUE source+id, + source, fetched_at)
                                   runs · quarantine · sync_state (B-1) · secrets (Fernet ciphertext) · alerts
                                                  ▼
       FastAPI /api/* (sign-in + roles, audit) ──►  UI: Overview · Events · Users · Devices · Integrations (FR-10)
                                                     · Add integration (B-5) · Actions & tickets · Audit log
                       ──►  actions: Jira ticket for incidents (real Jira, project KAN) · Slack on repeated failure (B-4)

  Real APIs: GitHub · Okta · Jira Cloud · NVD · CISA KEV      Test doubles only (tests/fakes, never started by the platform)
```

## Run it

Requires **Python 3.11+** (Mac or Windows).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run_all.py
```

On first run, `run_all.py` creates `.env` from `.env.example`, generates `SECRETS_KEY` (the vault master key) and creates three dashboard sign-ins, printing their passwords **once** (only scrypt hashes are stored in `.env`). Then it starts the platform at http://localhost:8000.

| Address | Who can open it |
|---|---|
| `/` | Everyone: the home page (no live data, no protected API calls; its code tabs embed the real configs: after changing one, run `python -m integration_platform.embed_configs`) |
| `/docs` | Everyone: the documentation (overview, quick start, config reference, schema, reliability, security, roles, FAQ) |
| `/login` | Everyone: the sign-in page (the home page opens the same card as a modal) |
| `/app` | Signed-in users only: the dashboard. Without a session it redirects to `/#signin`; signing out returns to `/` |

Set `DEMO_MODE=on` in `.env` to let the sign-in card pre-fill the username for the picked role and show "Demo accounts are configured in .env". Passwords are never shown, and the role always comes from the account on the server, not from the picked tab.

Tests: `python -m pytest`. There are 198 tests; they are hermetic and never read your `.env` or call real APIs.

## Sign-in, roles and audit

| Role | Can |
|---|---|
| **Viewer** | Read every page (Overview, Events, Users, Devices, Integrations, Actions & tickets) |
| **Analyst** | Viewer + **Run now** on a connection |
| **Admin** | Everything: Add integration (wizard, test, sample, AI mapping), enable / disable, resume, revoke and store secrets, demo controls, **Audit log** |

- The API enforces the rules (`auth.required_role`); the UI only mirrors them. Locked controls show a lock icon and "Admin only" / "Analyst only".
- Sessions are HMAC-signed HttpOnly cookies (SameSite=Lax, 12 h). Removing a user or changing their role ends their session. After 5 failed sign-ins for one username from one address, that pair waits 30 s (20 failures per address across usernames). Failed and blocked sign-ins are audited, and the error never says whether the username or the password was wrong.
- Change a password or add a user: `python -m integration_platform.auth set-password <user> <role>`.
- `GET /api/audit` (admin) lists sign-ins, denied calls and every change, with user, role, target and outcome. A demo reset never clears it.

## Add an integration (config, not code)

Use the **Add integration** wizard (Basics → Auth → Request → Pagination → Mapping → Test → Save), or drop a YAML file in `configs/integrations/` (live within 5 s). One config can have several streams:

```yaml
name: okta
display_name: "Okta"
base_url: "https://${OKTA_DOMAIN}"                 # non-secret settings can come from .env too
auth: { type: api_key, header: Authorization, prefix: "SSWS ", api_key: "${okta_token}" }   # secret by NAME only
scopes: ["okta.users.read", "okta.logs.read"]
schedule_seconds: 900                              # FR-4: every 15 minutes
rate_limit: { reset_header: x-rate-limit-reset, remaining_header: x-rate-limit-remaining }
streams:
  - name: users
    entity: user                                   # user | device | event
    endpoint: /api/v1/users
    params: { limit: 200 }
    pagination: { type: link }
    mapping:
      id: id
      name: "join(' ', [profile.firstName || '', profile.lastName || ''])"   # combine + nested values
      email: profile.email
      status: status
      last_login: lastLogin                        # dates converted to ISO 8601 UTC
  - name: events
    entity: event
    endpoint: /api/v1/logs
    params: { since: "{{ last_sync }}" }           # B-1 incremental sync
    pagination: { type: link }
    mapping: { id: uuid, type: eventType, severity: severity, timestamp: published, description: displayMessage }
    transforms: { severity_map: { DEBUG: info, INFO: info, WARN: medium, ERROR: high } }
```

Other options: `requires_env` (skip a stream unless a variable is set), `fallback_for` (use a stream only when another returns 403/404), `required_fields`, `default_severity`, `custom_step` (a rare plugin hook). The full JSON Schema is at `GET /api/schema`.

## Reliability rules (identical for every connector)

- **Timeouts, network errors, 5xx:** retry after exactly **1s, 2s, 4s**, then the run is **FAILED** with a clear error.
- **401/403:** never retried; health shows **"Authentication failed"**.
- **429:** the engine waits for `Retry-After` (seconds or an HTTP date). Without it, it uses the configured reset header (GitHub `x-ratelimit-reset`, Okta `x-rate-limit-reset`). Without that, exponential backoff. If the server says `Retry-After: 0` (NVD does), it waits the API's known window (`fallback_wait_seconds`) instead of hammering. Every wait is logged, e.g. "waited 5s due to Retry-After".
- **Proactive slow-down:** when `x-ratelimit-remaining` is near zero, the next call waits for the reset; `min_interval_seconds` paces APIs that ask for it (NVD keyless: 6 s).
- **Bad data:** a record with a missing required field, the wrong type, or an unparseable time is quarantined with its reason ("1 of N invalid"). The rest of the run is stored.
- **Repeated failure (B-4):** after `alert_after_failures` consecutive failed runs (default 3), the platform sends ONE alert per streak to `SLACK_WEBHOOK_URL` (and email if `SMTP_*` is set), plus a "recovered" message later. The UI banner and the log are always written.
- **Exfiltration guard:** a run that pulls more than 5x the rolling baseline auto-pauses the connection and raises a critical alert (which opens a Jira ticket). **Resume** accepts the new volume and re-learns the baseline from that point. Found with real data: GitHub's first Dependabot scan jumped from 2 to 183 records per run.

## Failure tests with real APIs (recorded outputs)

| Test | Real result |
|---|---|
| Wrong GitHub token (`api.github.com/user`) | `Authentication failed: HTTP 401 Unauthorized from https://api.github.com/user (not retried)`: 0 retries, 0.5 s |
| Controlled burst to NVD **without a key** (12 rapid requests) | Requests 1-11: HTTP 200. Request 12: **HTTP 429 with `Retry-After: 0`** and an HTML body. A first engine version backed off 1/2/4/8/16 s and still hit the 30 s rolling window. The fix: `fallback_wait_seconds: 30` for NVD. Result: `HTTP 429: waited 30s due to the rate-limit window (Retry-After said 0s)`, then all 14 records arrived (1 wait, 37 s). The shipped config also paces at 6 s, so normal runs never hit the limit. |
| Network off mid-run (stream pointed at unroutable `10.255.255.1`, 3 s timeout) | `timeout from http://10.255.255.1/logs - FAILED after 3 retries (waited 1s, 2s, 4s)`: retry log `timeout -> retry 1 in 1s / 2 in 2s / 3 in 4s`, 19 s |
| Record with a missing field (real CISA KEV feed, `cveID` removed from one record) | `1 of 1766 invalid (quarantined)`, stored 1765 of 1766, reason `missing required field id ('cveID' not found in record)` |
| NVD first sync (real) | 3,039 CVEs modified in the last 24 h fetched in 4 paced pages; the next run fetched 0 new (incremental window) |
| Real volume jump (GitHub's first Dependabot scan, 2 -> 183 records) | The guard paused GitHub and opened Jira ticket KAN-6. Before the fix, every later run re-paused it; after **Resume** the baseline is re-learnt and runs stay healthy |
| Real network drop during a scheduled run | All five connections: `connection failed … FAILED after 3 retries (waited 1s, 2s, 4s)`, shown as Failing; the next run recovered them |

All five sources run successfully with the keys in `.env`. Without a key, a card shows "Not configured" and nothing runs.

## Safe secrets & Git hygiene

- Configs contain only names (`${github_token}`). Values live in `.env` (git-ignored) and are encrypted into the vault on first use (Fernet, key `SECRETS_KEY`).
- No API ever returns a secret value. Logs (console and `logs/platform.log`) go through `logmask.MaskingFilter`, which masks every resolved secret value, bearer/basic/SSWS headers, JWTs, AWS keys and `key=value` secrets.
- `.gitignore` covers `.env`, `/data/` (DB and vault), `/logs/`, `*.db`, `*.log`, `.venv/` and `__pycache__/`. `tests/test_git_hygiene.py` scans `configs/` for secret-looking literals and scans every committed file and the logs for the real secret values from `.env`. It also checks that `.env`, the DB and the logs are untracked (`git check-ignore`).
- Token safety extras (INC-05): scopes with a write/admin badge, a "Rotate secret" warning by age, the exfiltration guard (auto-pause plus a critical alert), and **Revoke**, which wipes the secret and leaves a tombstone.

## 3-minute demo script

Before going on stage: `python run_all.py`, open http://localhost:8000 (the home page), sign in as **admin**, and open your Jira project `KAN` in another tab. If CISA KEV is already listed, remove it (⋯ → Delete integration) so step 2 can add it live.

1. **One common format (30 s).** **Overview**: connected tools, events and critical events in the last 24 h, events by severity. **Events**: GitHub Dependabot alerts, the Okta system log, NVD CVEs and Jira issues in one table; click a row for the normalised fields and the raw JSON. **Users**: Okta, Jira and GitHub accounts side by side.
   > "Different APIs, logins and paging. One schema, one store."
2. **Config, not code (45 s).** **Add integration**:
   - Basics: `CISA KEV`, `cisa_kev`, `https://www.cisa.gov`. Auth: **None**. Request: `/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Pagination: **None**.
   - Mapping: **Fetch sample from API** (1,766 records, 20 shown). The suggestion arrives with its engine badge (**AI · Sarvam** when `LLM_*` is set, otherwise **Rule-based**). Review it, then **Apply to config**.
   - **Run test** (raw vs normalised, nothing saved), then **Save and go live**. KEV events appear.
   > "That was the whole integration: a YAML file."
3. **Reliable by default (60 s).** **Demo controls** (sidebar, admin only):
   - **Call GitHub with a wrong key**: a real 401, "Authentication failed", no retries.
   - **Network off mid-run**: retries after 1 s, 2 s and 4 s, then the GitHub card turns red.
   - **Fail 3 times, then recover**: one alert (banner, log, Slack if configured), then "recovered".
4. **Safe secrets (20 s).** GitHub card → **View details**: the config shows only `${github_token}`, and the secret sits in the vault with its age. `git check-ignore -v .env data/platform.db logs/platform.log` proves none of them are tracked.
5. **Roles (15 s).** Sign in as **viewer**: everything is readable, **Run now** and the ⋯ actions are locked, and Add integration and Audit log show "Admin only". Back as admin, **Audit log** shows who did what.
6. **Bonus (30 s).** **Actions & tickets**: high and critical incidents from Okta and GitHub open tickets in Jira `KAN` (KAN-6 came from the exfiltration guard). CVE feeds are intel, not tickets.
   > "This is how INC-05 could have been caught."

## Project layout

```
integration_platform/  config.py (models, validation, ${NAME} resolution) · engine.py (auth, paging, retries, rate limits, runs)
                       normaliser.py (common schema, quarantine rules) · db.py (users/devices/events, runs, audit, vault rows)
                       auth.py (sign-in, roles, sessions) · vault.py · logmask.py · alerts.py (B-4) · actions.py · scheduler.py
                       ai_mapper.py · demo.py · api.py · static/ (app, home page and docs: plain HTML/CSS/JS, no build step, offline)
configs/integrations/  github, okta, jira, nvd (real) · cisa_kev (added live)
configs/actions/       create_jira_ticket.yaml (real Jira, project KAN) · slack_failure_alert.yaml (B-4)
configs/examples/      cisa_kev.yaml (what the live demo creates)
tests/                 198 tests, incl. test_access.py (roles, audit), test_public.py (public pages, sign-in) and test_git_hygiene.py
tests/fakes/           in-process fake tools for the tests (CloudTrail, Firewall, OAuth2 Okta, Jira) + their configs and kev.json
```
