# PlugSec: a Config-Driven Generic Integration Platform

**Add a new security tool with a config file, not code.** One generic engine reads the config, logs in, pages through the API, retries and slows down when it must, quarantines bad records, and maps everything into **one common schema**: users, devices and events. The schema lives in a single store, with a health page and alerts on repeated failure.

It works fully offline (mock tools, no LLM key needed) and against **real free-tier APIs** when keys are present.

## PRD traceability

| PRD line | Where it is implemented | How to see it in the demo |
|---|---|---|
| **Goal 1** Config, not code | `configs/integrations/*.yaml`, validated by `config.IntegrationConfig`; hot-loaded by `scheduler.Registry` | Demo step 2: CISA KEV added live from the wizard; no restart, no code |
| **Goal 2** One common format | `config.ENTITY_FIELDS` + `normaliser.normalise` -> `db.Database.store` | Demo step 1: **Users**, **Devices**, **Events** tabs |
| **Goal 3** Safe secrets | `config.SecretRef`, `vault.Vault` (Fernet), `logmask.MaskingFilter`, `.gitignore` | Demo step 4 |
| **Goal 4** Reliable by default | `engine.send_with_retry` / `rate_limit_wait` / quarantine in `engine.run_integration`, the same for every connector | Demo step 3 |
| **Goal 5** Visible health | `api._health`, Integrations tab | Demo step 5 |
| **Goal 6** 3+ real sources | `configs/integrations/{github,okta,jira,nvd}.yaml`, plus CISA KEV added live | "Real sources" table below |
| **FR-1** Auth: API key + more | `config.AuthApiKey` (with `prefix`, `optional`), `AuthBasic`, `AuthBearer`, `AuthOAuth2`; `engine.apply_auth` | Cards show `auth:` chips: Firewall api_key, Okta `SSWS` api_key, GitHub bearer, Jira basic, Mock Okta OAuth2 |
| **FR-2** Endpoints | `config.Stream.endpoint/method/params/headers`, `${VAR}` in URLs; `engine._Request`, `engine.render_params` | Each card lists its streams (`users -> user · link`) |
| **FR-3** Pagination (2+) | `config.Pagination{Page,Offset,Cursor,Link}`; `engine.page_params`, `engine.next_link`, stop rules in `engine.fetch_records` | GitHub/Okta link, Jira/NVD offset, Firewall page, CloudTrail NextToken |
| **FR-4** Schedule | `IntegrationConfig.schedule_seconds` (real sources: 900 = 15 min); `scheduler.Registry._schedule` (APScheduler) | Card chip `every 15 min`; "Run now" for the demo |
| **FR-5** Mapping | `Stream.mapping` (JMESPath: rename, nested paths, joins), `Stream.transforms` (`time_format`, `severity_map`); `normaliser.parse_time` / `map_severity` | Raw vs normalised view (click an event row; wizard Test step) |
| **FR-6** Secrets by name | Configs hold only `${github_token}` etc.; `config.resolve_env` -> `vault.Vault.get` (encrypted) -> env | Demo step 4 |
| **FR-7** Retries 1s/2s/4s then failed | `engine.send_with_retry` + `engine.backoff_seconds` (`RetrySpec` default 3 x base 1s); 401/403 never retried (`engine.AuthError`) | Demo controls: **Network off**, **Wrong key** |
| **FR-8** Rate limits | `engine.rate_limit_wait`: Retry-After (seconds or HTTP date) > reset header (`x-ratelimit-reset`, `x-rate-limit-reset`) > backoff; `engine._note_remaining` proactive slow-down; `min_interval_seconds` pacing; `fallback_wait_seconds` | Demo controls: **429 with Retry-After: 5** -> "waited 5s due to Retry-After" |
| **FR-9** Bad data | `normaliser.BadRecord` (missing required field / wrong type / unparseable time) -> `db.Database.quarantine`, per stream; the run continues | Demo controls: **malformed record** -> "1 of 13 invalid", card "N quarantined · View" |
| **FR-10** Health | `api._health`: status, last run, records pulled, per-entity counts, last error, retries, failure streak, "Not configured", "Authentication failed" | Integrations tab |
| **FR-11** One store, common schema | `db.py`: `users`, `devices`, `events` tables, `UNIQUE(source, id)`; every row has `source` + `fetched_at` | `GET /api/users`, `/api/devices`, `/api/events` |
| **B-1** Incremental sync | `{{ last_sync }}` / `last_sync_dt` in params (`engine.template_context`), stored per stream (`db.set_last_sync`) | Okta `since`, NVD `lastModStartDate`, CloudTrail `StartTime` |
| **B-2** Config validation | pydantic models + `config.friendly_errors`; `POST /api/integrations/validate`; checked per wizard step | Wizard: empty Basics / literal secret are blocked with clear messages |
| **B-3** Test connection | `engine.dry_run_integration`, `POST /api/integrations/test` (nothing saved) | Wizard **Test** step: raw vs normalised |
| **B-4** Alert on repeated failure | `alerts.FailureAlerter` -> action engine (`actions.ActionRunner.notify`, `configs/actions/slack_failure_alert.yaml`), optional SMTP, UI banner + log | Demo controls: **Fail 3 times, then recover** -> Slack message |
| **B-5** Web form -> config | `static/app.js` wizard with a live YAML panel (two-way) | Add Integration tab |

## Real sources (Section 4): each differs in login type and paging style

| Source | Login type | Paging style | Streams -> entity | Config |
|---|---|---|---|---|
| **GitHub REST API** | Bearer (fine-grained PAT, read-only) | Link header, page numbers (`per_page=100`) | `me`, `collaborators`, `org_members` (if `GITHUB_ORG`) -> users; `dependabot_alerts` -> events, falling back to `repo_events` if Dependabot is unavailable | `github.yaml` |
| **Okta (Integrator Free)** | API token header `Authorization: SSWS …` | Link header with `after` cursor | `/api/v1/users` -> users; `/api/v1/logs` (incremental `since`) -> events | `okta.yaml` |
| **Jira Cloud (free)** | Basic (email + API token) | Offset `startAt` / `maxResults` (issues: `/search/jql` token paging) | `/rest/api/3/users/search` -> users; issues -> events | `jira.yaml` |
| **NVD CVE API 2.0** | Optional API key header `apiKey` | Offset `startIndex` / `resultsPerPage` / `totalResults` | CVEs -> events (severity from CVSS v3.1, falling back to v3.0, then v2) | `nvd.yaml` |
| **CISA KEV** | None | None | KEV -> events. **Added live in the demo** (saved offline copy at `mocks/data/kev.json`) | `configs/examples/cisa_kev.yaml` |
| Mock Okta (OAuth2) | OAuth2 client credentials + scopes | Link header | users + events | `mock_okta.yaml` |
| Acme Firewall (mock) | API key header | Page number + `total_pages` | events + **devices** (every device field) | `acme_firewall.yaml` |
| AWS CloudTrail (mock) | Bearer | Cursor `NextToken` | events | `aws_cloudtrail.yaml` |

Real sources run every 15 minutes, with read-only endpoints and scopes only. Missing settings never cause errors: the card says **"Not configured: set `github_token`, `GITHUB_OWNER` …"** and nothing runs.

**Connect the real sources:** fill these in `.env` (names only ever appear in configs):

```
github_token=   GITHUB_OWNER=   GITHUB_REPO=   (optional GITHUB_ORG=)
okta_token=     OKTA_DOMAIN=integrator-1234567.okta.com
jira_email=     jira_token=     JIRA_DOMAIN=yourteam.atlassian.net
nvd_api_key=    (optional)
```

Then click **Run now** on each card.

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
       FastAPI /api/*  ──►  UI: Events · Users · Devices · Integrations (health, FR-10) · Add Integration (B-5) · Actions
                       ──►  actions: Jira ticket for incidents (bonus) · Slack on repeated failure (B-4)

  Real APIs: GitHub · Okta · Jira Cloud · NVD · CISA KEV        Mocks (offline): CloudTrail · Firewall · Okta OAuth2 · Jira/Slack
```

## Run it

Requires **Python 3.11+** (Mac or Windows).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run_all.py
```

On first run, `run_all.py` creates `.env` from `.env.example` (or upgrades an older `.env`) and generates `SECRETS_KEY`, the vault master key. It then starts the platform plus four mocks: http://localhost:8000 (dashboard), mock tools on ports :9001 to :9003, and the mock Jira board and Slack inbox on :9004 (`/` and `/slack`).

Tests: `python -m pytest`. There are 173 tests; they are hermetic and never read your `.env` or call real APIs.

## Add an integration (config, not code)

Use the **Add Integration** wizard (Basics → Auth → Request → Pagination → Mapping → Test → Save), or drop a YAML file in `configs/integrations/` (live within 5 s). One config can have several streams:

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

## Failure tests with real APIs (recorded outputs)

| Test | Real result |
|---|---|
| Wrong GitHub token (`api.github.com/user`) | `Authentication failed: HTTP 401 Unauthorized from https://api.github.com/user (not retried)`: 0 retries, 0.5 s |
| Controlled burst to NVD **without a key** (12 rapid requests) | Requests 1-11: HTTP 200. Request 12: **HTTP 429 with `Retry-After: 0`** and an HTML body. A first engine version backed off 1/2/4/8/16 s and still hit the 30 s rolling window. The fix: `fallback_wait_seconds: 30` for NVD. Result: `HTTP 429: waited 30s due to the rate-limit window (Retry-After said 0s)`, then all 14 records arrived (1 wait, 37 s). The shipped config also paces at 6 s, so normal runs never hit the limit. |
| Network off mid-run (stream pointed at unroutable `10.255.255.1`, 3 s timeout) | `timeout from http://10.255.255.1/logs - FAILED after 3 retries (waited 1s, 2s, 4s)`: retry log `timeout -> retry 1 in 1s / 2 in 2s / 3 in 4s`, 19 s |
| Record with a missing field (real CISA KEV feed, `cveID` removed from one record) | `1 of 1766 invalid (quarantined)`, stored 1765 of 1766, reason `missing required field id ('cveID' not found in record)` |
| NVD first sync (real) | 3,039 CVEs modified in the last 24 h fetched in 4 paced pages; the next run fetched 0 new (incremental window) |

GitHub, Okta and Jira **success** runs need your keys in `.env`. Until those keys are added, those cards show "Not configured" and nothing runs.

## Safe secrets & Git hygiene

- Configs contain only names (`${github_token}`). Values live in `.env` (git-ignored) and are encrypted into the vault on first use (Fernet, key `SECRETS_KEY`).
- No API ever returns a secret value. Logs (console and `logs/platform.log`) go through `logmask.MaskingFilter`, which masks every resolved secret value, bearer/basic/SSWS headers, JWTs, AWS keys and `key=value` secrets.
- `.gitignore` covers `.env`, `/data/` (DB and vault), `/logs/`, `*.db`, `*.log`, `.venv/` and `__pycache__/`. `tests/test_git_hygiene.py` scans `configs/` for secret-looking literals and scans every committed file and the logs for the real secret values from `.env`. It also checks that `.env`, the DB and the logs are untracked (`git check-ignore`).
- Token safety extras (INC-05): scopes with a write/admin badge, a "Rotate secret" warning by age, the exfiltration guard (auto-pause plus a critical alert), and **Revoke**, which wipes the secret and leaves a tombstone.

## 3-minute demo script

Before going on stage: `python run_all.py`, open http://localhost:8000 (keep **⚙ → Demo controls** handy), http://localhost:9004 (Jira) and http://localhost:9004/slack (Slack). Then **⚙ → Reset demo**.

1. **One common format (30 s).** **Users** tab: GitHub, Okta and Jira users (Mock Okta offline) in one table: name, email, status, last_login, plus **source** and **fetched_at**. **Events** tab: GitHub, Okta, NVD and mock records with type, severity, timestamp and description. **Devices** tab: the firewall's device inventory, with every field filled.
   > "Different APIs, logins and paging. One schema, one store."
2. **Config, not code (45 s).** **Add Integration**:
   - Basics: `CISA KEV`, `cisa_kev`, `https://www.cisa.gov`.
   - Auth: **None**.
   - Request: `/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
   - Pagination: **None**.
   - Mapping: **Fetch sample from API** (1,766 records, 20 shown). The suggestion gives `id ← cveID`, `timestamp ← dateAdded`, `description ← vulnerabilityName`, `type = 'vulnerability'`, and default severity high. Click **Apply**.
   - Then **Run test** and **Save**. KEV events appear.
   > "That was the whole integration: a YAML file."
3. **Reliable by default (60 s).** In **Demo controls**:
   - **Call GitHub with a wrong key**: a real 401, "Authentication failed", no retries.
   - **429 with Retry-After: 5**: "waited 5s due to Retry-After".
   - **Send a malformed record**: "1 of 13 invalid", the run continues; **View** shows the reason.
   - **Network off mid-run**: retries at 1s, 2s, 4s, then FAILED; the card turns red.
   - **Fail 3 times, then recover**: one Slack alert in `#soc-alerts`, then "recovered".
4. **Safe secrets (20 s).** **View config** on GitHub shows only `${github_token}`. The vault holds Fernet ciphertext. `logs/platform.log` is clean. `git check-ignore -v .env data/platform.db logs/platform.log` proves none of them are tracked.
5. **Health page (15 s).** Each card reads "Okta: Healthy, 2m ago, 1,240 users, 310 events", with last run, records pulled, retries, last error, quarantined, "Not configured" and "Authentication failed" states.
6. **Bonus (30 s).** High/critical incidents became Jira tickets automatically (CVE feeds excluded). **Simulate stolen-token bulk export**: AWS CloudTrail is auto-paused as SUSPICIOUS, a critical alert fires, and a Jira ticket is created.
   > "This is how INC-05 could have been caught."

## Project layout

```
integration_platform/  config.py (models, validation, ${NAME} resolution) · engine.py (auth, paging, retries, rate limits, runs)
                       normaliser.py (common schema, quarantine rules) · db.py (users/devices/events + runs, vault rows)
                       vault.py · logmask.py · alerts.py (B-4) · actions.py · scheduler.py · ai_mapper.py · demo.py · api.py
                       static/ (UI)
configs/integrations/  github, okta, jira, nvd (real) · aws_cloudtrail, acme_firewall, mock_okta (mocks)
configs/actions/       create_jira_ticket.yaml · slack_failure_alert.yaml (B-4)
configs/examples/      cisa_kev.yaml (what the live demo creates)
mocks/                 mock_cloudtrail, mock_firewall (+devices), mock_okta (OAuth2), mock_jira (+Slack inbox), data/kev.json
tests/                 173 tests, including test_git_hygiene.py
```
