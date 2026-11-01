# Requirements traceability

Where each PRD line is implemented and how to see it in the demo.

[← Back to the docs index](README.md)

## PRD traceability

| PRD line | Where it is implemented | How to see it in the demo |
|---|---|---|
| **Goal 1** Config, not code | `configs/integrations/*.yaml`, validated by `config.IntegrationConfig`; hot-loaded by `scheduler.Registry` | Demo step 2: CISA KEV added live from **Add integration**; no restart, no code |
| **Goal 2** One common format | `config.ENTITY_FIELDS` + `normaliser.normalise` -> `db.Database.store` | Demo step 1: **Overview**, **Events**, **Users** pages |
| **Goal 3** Safe secrets | `config.SecretRef`, `vault.Vault` (Fernet), `logmask.MaskingFilter`, `.gitignore` | Demo step 4 |
| **Goal 4** Reliable by default | `engine.send_with_retry` / `rate_limit_wait` / quarantine in `engine.run_integration`, the same for every connector | Demo step 3 |
| **Goal 5** Visible health | `api._health`, Integrations tab | Demo step 5 |
| **Goal 6** 3+ real sources | `configs/integrations/{github,okta,jira,nvd,tailscale}.yaml`, plus CISA KEV added live | "Real sources" table below |
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
| **Multiple endpoints per integration** | `IntegrationConfig.streams` (shared base URL, login, headers, retries, rate limits; per-stream path, paging, mapping, entity); wizard **Endpoints** step (add / duplicate / remove), per-endpoint **Mapping** tabs (fetch sample, AI suggest, path check via `POST /api/mapping/check`) and per-endpoint **Test** badges; `api._stream_status` | Demo step 3: a 2-endpoint integration built in the wizard; integration drawer lists every endpoint with records, last status, last error |
| **for_each fan-out** (generic) | `config.ForEach`, `Stream.merge_into_parent` / `parent_status`, `IntegrationConfig.ordered_streams`; `engine.fan_out` (semaphore, per-item 403/404 skip with reasons, shared rate-limit hold), `engine.render_path` (sandboxed, parent fields only, URL-encoded); `normaliser` functions `parent()`, `base64_decode`, `first_paragraph`, `percent_map` | `tests/test_for_each.py`; GitHub languages / README / Dependabot per repository |
| **Real device source + new-device detection** | `configs/integrations/tailscale.yaml` (config only); generic `Stream.new_record_event` (`engine.new_record_event`), JMESPath filters in `records_path` with `days_until()` | **Devices**: Tailscale (real) first in the source filter, Online / Offline · x min ago dot; **Events**: "New device joined: … by …" |
| **All GitHub repositories** (config only) | `configs/integrations/github.yaml`: `repositories` (`/user/repos`, Link paging) + `repo_languages`, `repo_readme`, `dependabot_alerts` via `for_each`; `repository` entity + `repositories` table; `GET /api/repositories` | **Repositories** page (all roles): KPIs, filters, cards, drawer; GitHub card "N repositories · N alerts · N endpoints" |
