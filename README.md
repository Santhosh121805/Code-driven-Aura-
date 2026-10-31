# Integration Hub: a Config-Driven Generic Integration Platform

Add a new security-tool integration (a firewall, Okta, AWS…) **without writing code**. Describe the tool's API in a guided form (or YAML). One generic engine then:

- fetches, paginates and retries;
- quarantines bad records;
- watches for token abuse;
- normalises everything into one OCSF-style alert schema;
- triggers outbound actions, such as Jira tickets for high/critical alerts.

It runs fully offline: no CDNs and no internet needed. The AI mapping assistant falls back to a rule-based matcher when no LLM key is configured.

## Architecture

```
                 ┌──────────────────────────── Platform (FastAPI, :8000) ─────────────────────────────┐
  Browser ──────►│  UI (static HTML/JS)   REST API (/api/...)   Demo controls (/api/demo/...)         │
  (4 tabs)       │        │                    │                                                      │
                 │        ▼                    ▼                                                      │
                 │  ┌─────────────┐   ┌──────────────────┐   ┌──────────────────────────────────────┐ │
  configs/       │  │ config.py   │──►│ scheduler.py     │──►│ engine.py (ONE engine for any tool)   │ │
  integrations/  │  │ pydantic    │   │ APScheduler, hot │   │ auth → paginate → retry → records     │ │
  *.yaml ───────►│  │ validation, │   │ load, auto-pause │   │ → normalise / QUARANTINE bad records  │ │
  actions/*.yaml │  │ ${ENV} refs │   │ resume / revoke  │   │ → EXFILTRATION GUARD (volume baseline)│ │
                 │  └─────────────┘   └──────────────────┘   └───────────────────┬──────────────────┘ │
                 │  ┌──────────────┐  ┌──────────────────┐   ┌──────────────────▼──────────────────┐  │
                 │  │ ai_mapper.py │  │ vault.py         │   │ db.py (SQLite): events (UNIQUE      │  │
                 │  │ rules + LLM, │  │ Fernet-encrypted │   │ source,id), runs, quarantine,       │  │
                 │  │ verified     │  │ secrets, age,    │   │ connector state, secrets ciphertext │  │
                 │  └──────────────┘  │ revoke; logmask  │   └──────────────────┬──────────────────┘  │
                 │                    └──────────────────┘   ┌──────────────────▼──────────────────┐  │
                 │                                           │ actions.py: Jinja2 sandbox, dedupe  │  │
                 │                                           │ key → exactly one ticket per event  │  │
                 │                                           └──────────────────┬──────────────────┘  │
                 └──────────────────────────────────────────────────────────────┼─────────────────────┘
          ▲ bearer / api-key / OAuth2 client credentials                        │ POST /rest/api/3/issue
  ┌───────┴──────────────┬───────────────────┬──────────────────────┐   ┌───────▼──────┐
  │ Mock AWS CloudTrail  │ Mock Firewall     │ Mock Okta System Log │   │ Mock Jira    │
  │ :9001 bearer,        │ :9002 X-API-Key,  │ :9003 OAuth2 + scope,│   │ :9004 board  │
  │ NextToken pages      │ page numbers, 429 │ Link rel="next"      │   │              │
  └──────────────────────┴───────────────────┴──────────────────────┘   └──────────────┘
```

**Normalised schema:** `source, event_id, time (ISO 8601 UTC), severity (info|low|medium|high|critical), title, host, src_ip, dst_ip, user, raw`

## Run it

Requires **Python 3.11+** (Mac or Windows).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run_all.py
```

On first run, `run_all.py` does three things:
1. It copies `.env.example` to `.env` (if your `.env` is older, it adds any missing settings).
2. It generates `SECRETS_KEY`, the vault master key.
3. It starts the platform plus 4 mock tools as separate processes and waits until each one is healthy.

| Service | URL |
|---|---|
| Dashboard | http://localhost:8000 |
| Mock AWS CloudTrail: bearer, `NextToken` pagination, CloudTrail records (also `/kev` public feed) | http://localhost:9001 |
| Mock Firewall: `X-API-Key`, page pagination, HTTP 429 | http://localhost:9002 |
| Mock Okta System Log: OAuth2 client credentials (`okta.logs.read`), `Link: rel="next"`; **not preconfigured** | http://localhost:9003 |
| Mock Jira board (auto-refreshing) | http://localhost:9004 |

Docker alternative: `docker compose up --build`, then open the same URLs.

Tests: `python -m pytest`. There are 107 tests; the mocks run in-process, so no ports or network are needed.

**Demo mode:** `DEMO_MODE=on` is the default. Random faults are off, and you trigger them on cue from **⚙ → Demo controls**. With `DEMO_MODE=off`, about 1 in 5 firewall requests returns HTTP 429 and about 1 in 15 records is malformed. `FIREWALL_RATE_LIMIT` and `MALFORMED_RECORDS` set to `on`/`off` override either default.

**LLM (optional):** set `ANTHROPIC_API_KEY` (default model `claude-opus-5-5`), or `LLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` for any OpenAI-compatible endpoint. Without either, the rule-based engine is used.

## Add an integration (no code)

**In the UI:** open the **Add Integration** tab. Seven steps take you from Basics to Save, with a **live YAML panel** beside the form. Form and YAML edit the same object, so you can edit either one.

1. **Basics**: name, display name, base URL, poll interval.
2. **Auth**: `none | bearer | api_key | basic | oauth2_client_credentials`, plus **scopes**.
   - Secret fields accept only `${ENV_VAR}` references. **🔒 Store a value in the vault…** encrypts a pasted secret and fills in the reference for you.
   - A write/admin scope shows a warning badge.
3. **Request**: endpoint, method, params. Use `{{ last_sync }}` in a param for incremental sync.
4. **Pagination**: `none | page | offset | cursor | link`.
   - `link` follows `Link: <…>; rel="next"` (Okta/GitHub style), or a URL in the body via `next_path`.
   - Next links that point to another host are refused, because the token would be sent there.
5. **Mapping**: click **Fetch sample from API**, then **Suggest mapping**. Review the editable table (tool field, example, confidence) and click **Apply**.
6. **Test**: runs once **without saving**. It shows the first 5 records raw vs normalised, plus any that would be quarantined.
7. **Save**: writes `configs/integrations/<name>.yaml` and the integration goes live immediately.

**As a file:** drop a YAML into `configs/integrations/`; it goes live within 5 seconds. This is what the wizard produces for Okta:

```yaml
name: okta
display_name: "Mock Okta"
base_url: "http://localhost:9003"
auth:
  type: oauth2_client_credentials
  token_url: "/oauth2/v1/token"
  client_id: "${OKTA_CLIENT_ID}"
  client_secret: "${OKTA_CLIENT_SECRET}"
scopes: ["okta.logs.read"]              # least privilege; requested at the token endpoint
request: { endpoint: "/api/v1/logs" }
pagination: { type: link }             # follow Link: rel="next"
mapping: { event_id: uuid, time: published, severity: severity, title: displayMessage,
           src_ip: client.ipAddress, user: actor.alternateId }
transforms:
  severity_map: { DEBUG: info, INFO: info, WARN: medium, ERROR: critical }
  time_format: iso8601
required_fields: [event_id, time]      # records without these are quarantined
secret_max_age_days: 90                # health warns "Rotate secret" after this
exfiltration_guard: { multiplier: 5, min_records: 50, baseline_runs: 10, min_baseline_runs: 3 }
```

Mapping values are JMESPath expressions. AWS CloudTrail, for example, has no severity field, so its config builds one from `eventName` plus the outcome and maps it with `severity_map`: `DeleteTrail`/`StopLogging` → critical, `PutBucketPolicy` → high, a failed `ConsoleLogin` → medium. See `configs/integrations/aws_cloudtrail.yaml`. The full JSON Schema is at `GET /api/schema`.

**Plugin hook (rarely needed):** `custom_step: "package.module.ClassName"`, a class with `process(records, config) -> records` that runs before mapping. See `integration_platform/plugins/example_step.py` and `configs/examples/cisa_kev.yaml`.

**Actions** are config too (`configs/actions/*.yaml`). Each has a `when` filter, a sandboxed Jinja2 `body_template`, a `dedupe_key` and a `response_ticket_path`. The dedupe key is claimed atomically before sending, so an event can never create two tickets.

## Data quality: quarantine

A record that cannot be ingested safely goes to a **quarantine** table with its source, the raw record, a reason and the time. The run **continues** with the remaining records. Three things put a record there:
- a missing required field: "missing required field event_id ('eventID' not found in record)";
- a wrong type: "wrong type for src_ip: 'src' is a list, expected a single value";
- an unparseable time: "unparseable time 'N/A' in 'ts' (expected epoch_s)".

The health card shows **"N quarantined · View"** and lists each record with its reason.

## Token safety (brief INC-05: the 2025 Salesloft Drift stolen-OAuth-token breach)

In INC-05, attackers used OAuth tokens stolen from one integration to bulk-export customer data from many companies. This platform holds tokens for every connected tool, so it protects them in five ways:

| Control | How |
|---|---|
| **Encrypted at rest** | Secrets live in a Fernet-encrypted vault in SQLite. The key is `SECRETS_KEY`, generated into `.env` on first run. Configs hold only `${NAME}` references, and no API ever returns a secret value. |
| **Masked logs** | Every log line and stored error message is filtered: bearer/basic/SSWS credentials, `client_secret=…`, `access_token`, JWTs, Fernet tokens, AWS access keys, and any secret value the engine has resolved. |
| **Least privilege** | Each connector declares `scopes:`. A write/admin-looking scope shows a red badge. For OAuth2 the scopes are requested at the token endpoint, and the mock Okta returns 403 when `okta.logs.read` is missing. |
| **Rotation** | Secret age is tracked per connector. Health shows **"Rotate secret: … is 95 days old (policy 90)"**; the demo backdates the firewall key with `SECRET_AGE_OVERRIDES`. |
| **Exfiltration guard** | Each connector keeps a rolling baseline: the median records-per-run of its last 10 successful runs. A run above **max(min_records, 5× baseline)** marks the connector **SUSPICIOUS** and **auto-pauses** it. It also stores a critical alert, *"Possible token abuse: abnormal data volume from <connector>"*, which goes through the normal Jira action. The card turns red with **Review / Resume / Revoke**. **Revoke** disables the connector and wipes its secret, leaving a revocation record behind so `.env` cannot bring the secret back. |

## 2-minute demo script

Before going on stage: `python run_all.py`, open http://localhost:8000 and http://localhost:9004 side by side, then **⚙ → Reset demo**. Keep **⚙ → Demo controls** handy.

1. **One format for many tools (15 s):** the **Alerts** tab shows the Firewall (page API, epoch seconds, `HIGH`/`LOW`) and AWS CloudTrail (NextToken API, ISO times, severity derived from `eventName`) in **one table and one schema**. Click a row to see the raw record next to the normalised one.
   > "Two vendors, two different APIs, one engine. The only difference is a YAML file."

2. **Add Okta live, no code (45 s):** go to **Add Integration**.
   - Basics: `Mock Okta`, `okta`, `http://localhost:9003`
   - Auth: **OAuth2 client credentials**, client id `${OKTA_CLIENT_ID}`, secret `${OKTA_CLIENT_SECRET}`. Type `okta.users.manage` in Scopes to show the warning badge, then change it to `okta.logs.read`.
   - Request: `/api/v1/logs`
   - Pagination: **Next link (Link header)**
   - Mapping: **Fetch sample from API** gives an instant suggestion. Point out `ERROR → critical`, `actor.alternateId` found inside a nested object, and the confidence bars. Click **Apply**.
   - Then **Run test**, **Save & go live**.
   - On **Alerts**, a critical Okta event appears with a **SOC-n** ticket, which also shows on the Jira board.

3. **Bad data never stops the feed (15 s):** **Demo controls → Send a malformed record on next run**. On the Firewall card, **"1 quarantined" → View** shows *unparseable time 'N/A'*, and the run still ingested its other 12 records.

4. **Resilience (10 s):** **Demo controls → Trigger 429 on next Firewall run**. The card turns **amber: "Recovered after 2 retries"**: two HTTP 429s, exponential backoff, no data lost.

5. **Stolen token (30 s):** **Demo controls → Simulate stolen-token bulk export**.
   - The next AWS CloudTrail page returns about 20× normal volume, all `GetObject` calls from `svc-sales-integration` at a foreign IP.
   - The guard flags it right away: the card turns **red, "SUSPICIOUS: auto-paused (88 records vs baseline 12)"**.
   - A critical alert, *"Possible token abuse: abnormal data volume from AWS CloudTrail"*, appears with a Jira ticket.
   - Click **Review**, then **Revoke**. The token is wiped from the vault.
   > "This is how INC-05 could have been caught: one integration token suddenly pulling 7× its normal volume, paused within one run instead of exfiltrating for days."

Closing line:
> "Every new tool is a config file, not a sprint. And every token it holds is encrypted, least-privilege, rotated and watched."

## Project layout

```
integration_platform/   config.py · engine.py · normaliser.py · actions.py · scheduler.py · ai_mapper.py
                        vault.py (encrypted secrets) · logmask.py · demo.py · db.py · api.py · plugins/ · static/ (UI)
configs/integrations/   aws_cloudtrail.yaml, acme_firewall.yaml   (one file per integration)
configs/actions/        create_jira_ticket.yaml
configs/examples/       cisa_kev.yaml (no-auth feed + custom_step example)
mocks/                  mock_cloudtrail.py, mock_firewall.py, mock_okta.py, mock_jira.py, common.py, data/kev.json
tests/                  pytest suite
run_all.py              one-command launcher
```

The Python package is named `integration_platform` rather than `platform`, because a top-level `platform` package would shadow Python's standard-library `platform` module.
