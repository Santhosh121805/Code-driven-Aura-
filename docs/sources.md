# Connected tools and real runs

The real sources, how each one logs in and pages, and the results of real runs.

[← Back to the docs index](README.md)

## Real sources (Section 4): each differs in login type and paging style

| Source | Login type | Paging style | Streams -> entity | Config |
|---|---|---|---|---|
| **GitHub REST API** | Bearer (fine-grained PAT, read-only: Metadata, Contents, Dependabot alerts) | Link header, page numbers (`per_page=100`) | `repositories` (every repo the token sees) -> repositories, with `repo_languages` and `repo_readme` merged in per repo (`for_each`); `dependabot_alerts` per repo -> events (`resource` = repo); `me`, `collaborators`, `org_members` (if `GITHUB_ORG`) -> users | `github.yaml` |
| **Okta (Integrator Free)** | API token header `Authorization: SSWS …` | Link header with `after` cursor | `/api/v1/users` -> users; `/api/v1/logs` (incremental `since`) -> events | `okta.yaml` |
| **Jira Cloud (free)** | Basic (email + API token) | Offset `startAt` / `maxResults` (issues: `/search/jql` token paging) | `/rest/api/3/users/search` -> users; issues -> events | `jira.yaml` |
| **NVD CVE API 2.0** | Optional API key header `apiKey` | Offset `startIndex` / `resultsPerPage` / `totalResults` | CVEs -> events (severity from CVSS v3.1, falling back to v3.0, then v2) | `nvd.yaml` |
| **CISA KEV** | None | None | KEV -> events. **Added live in the demo** | `configs/examples/cisa_kev.yaml` |
| **Tailscale API v2** (free personal plan) | Bearer (API access token, in the vault) | None (one call returns every device) | `/api/v2/tailnet/-/devices` -> devices (every 60 s; "New device joined" event the first time a device id appears); the same response -> `update_available` (low) and `key_expiry` (medium, key expires within 7 days) events | `tailscale.yaml` |

Tailscale is the real device source: **Devices** shows its laptops and phones with an Online / Offline dot. Fake tools exist only as test doubles in `tests/fakes/`; the platform never loads or starts them.

Real sources run every 15 minutes, with read-only endpoints and scopes only. Missing settings never cause errors: the card says **"Not configured: set `github_token`, `GITHUB_OWNER` …"** and nothing runs.

**Connect the real sources:** fill these in `.env` (names only ever appear in configs):

```
github_token=   GITHUB_OWNER=   GITHUB_REPO=   (optional GITHUB_ORG=)
okta_token=     OKTA_DOMAIN=integrator-1234567.okta.com
jira_email=     jira_token=     JIRA_DOMAIN=yourteam.atlassian.net
nvd_api_key=    (optional)
```

Then click **Run now** on each card. High and critical incidents from Okta and GitHub open tickets in your Jira project `KAN` (`configs/actions/create_jira_ticket.yaml`); CVE feeds and Jira's own issues are never ticketed.

**Live data is real data only.** Overview, Events, Users, Devices and Repositories leave out every integration labelled "(Mock)" (`api.mock_sources`). The Demo source (Mock) exists only so the demo controls can show 429 / Retry-After, a malformed record and a bulk export; its run results appear in the control's result box, on its Integrations card and in Actions & tickets.

### Real Tailscale run

2 devices (1 Windows laptop, 1 Android phone), both with a Tailscale IP and owner; the laptop **Online**, the phone **Offline · 8 min ago** at the time of the run. The first sync raised one "New device joined" event per device; re-runs raise none. No client updates pending and no key expiring within 7 days (keys expire 2027-04-29), so those two event streams correctly returned 0.

### Real GitHub run (fine-grained token, all repositories, read-only)

| Measure | Result |
|---|---|
| Repositories found | **141** (100 public, 41 private; 30 forks, 0 archived) |
| Have a description | 22 |
| README summary (no description) | 81 (`summary_source = README`); 28 repos have no README (HTTP 404, skipped); 10 READMEs were template boilerplate only, so no summary |
| No description and no summary | 38 |
| Have topics | 0 (GitHub returns an empty `topics` list for every one of these repos) |
| Language breakdown | 127 repos, 45 languages |
| Dependabot | enabled on 1 repo, disabled on 134, no access on 6 (403 "Resource not accessible by personal access token") |
| Open alerts per severity | critical 17 · high 87 · medium 68 · low 9 (181, all in one repo) |
| Items skipped (recorded, run still **success**) | 168: 134 × "Dependabot alerts are disabled", 6 × "not accessible", 28 × README "Not Found" |
| API calls | about 406 per run (238 pages + 168 skipped items) of GitHub's 5,000 / hour; 3,940 left after the measured run. Schedule: hourly |
| Jira tickets | 0: `create_jira_ticket` skips `dependabot_alert` events (`when.type_not_in`), so 181 alerts did not flood `KAN` |
