# Reliability and security

Retry, rate-limit and bad-data rules, recorded failure tests with real APIs, and secret hygiene.

[← Back to the docs index](README.md)

## Reliability rules (identical for every connector)

- **Timeouts, network errors, 5xx:** retry after exactly **1s, 2s, 4s**, then the run is **FAILED** with a clear error.
- **401/403:** never retried; health shows **"Authentication failed"**.
- **429:** the engine waits for `Retry-After` (seconds or an HTTP date). Without it, it uses the configured reset header (GitHub `x-ratelimit-reset`, Okta `x-rate-limit-reset`). Without that, exponential backoff. If the server says `Retry-After: 0` (NVD does), it waits the API's known window (`fallback_wait_seconds`) instead of hammering. Every wait is logged, e.g. "waited 5s due to Retry-After".
- **Proactive slow-down:** when `x-ratelimit-remaining` is near zero, the next call waits for the reset; `min_interval_seconds` paces APIs that ask for it (NVD keyless: 6 s).
- **Bad data:** a record with a missing required field, the wrong type, or an unparseable time is quarantined with its reason ("1 of N invalid"). The rest of the run is stored.
- **Repeated failure (B-4):** after `alert_after_failures` consecutive failed runs (default 3), the platform sends ONE alert per streak to `SLACK_WEBHOOK_URL` (and email if `SMTP_*` is set), plus a "recovered" message later. The UI banner and the log are always written. Slack messages have a short title (⚠️ failing / ✅ recovered), the connector, status, last error (masked), time and a button to the Integrations page; **Demo controls → Send a test message** posts "PlugSec: Slack alerts connected". If Slack rejects or cannot be reached, the failure is logged and shown in the banner; retries are bounded (1/2/4 s on 5xx, none on 4xx) and never repeat for the same streak.
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
