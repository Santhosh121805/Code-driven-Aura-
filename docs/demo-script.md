# 3-minute demo script

A timed walkthrough of the main features.

[← Back to the docs index](README.md)

## 3-minute demo script

Before going on stage: `python run_all.py`, open http://localhost:8000 (the home page), sign in as **admin**, and open your Jira project `KAN` in another tab. If CISA KEV is already listed, remove it (⋯ → Delete integration) so step 2 can add it live.

1. **One common format (30 s).** **Overview**: connected tools, events and critical events in the last 24 h, events by severity. **Events**: GitHub Dependabot alerts, the Okta system log, NVD CVEs and Jira issues in one table; click a row for the normalised fields and the raw JSON. **Users**: Okta, Jira and GitHub accounts side by side.
   > "Different APIs, logins and paging. One schema, one store."
2. **Config, not code (45 s).** **Add integration**:
   - Basics: `CISA KEV`, `cisa_kev`, `https://www.cisa.gov`. Auth: **None**. Endpoints: one endpoint, path `/sites/default/files/feeds/known_exploited_vulnerabilities.json`, pagination **None**.
   - Mapping: **Fetch sample from API** (1,766 records, 20 shown). The suggestion arrives with its engine badge (**AI · Sarvam** when `LLM_*` is set, otherwise **Rule-based**). Review it, then **Apply to config**.
   - **Run test** (raw vs normalised, nothing saved), then **Save and go live**. KEV events appear.
   > "That was the whole integration: a YAML file."
3. **Multiple endpoints (40 s).** **Add integration** → **Start over**:
   - Basics: `Two-endpoint demo (Mock)`, `two_endpoint_demo`, `http://127.0.0.1:8000/mock`. Auth: **None**.
   - Endpoints: endpoint 1 `events` (Events, `/events`); **+ Add endpoint** → `devices` (Devices, `/devices`). The live YAML shows both streams.
   - Mapping: the `events` tab → **Fetch sample** → **Apply**; the `devices` tab → same. Each mapped path gets a ✓ and an example from the sample.
   - **Run test**: one tab per endpoint, each with a **Pass** badge, raw vs normalised. **Save and go live**; the card shows "2 endpoints" and the drawer lists each with records and last status.
   - **Repositories**: every GitHub repo with its description or README summary, languages and Dependabot alerts, filled by the same `for_each` feature.
   > "One login, several endpoints, each with its own mapping. GitHub's per-repository calls are config too."
4. **Reliable by default (60 s).** **Demo controls** (sidebar, admin only):
   - **Call GitHub with a wrong key**: a real 401, "Authentication failed", no retries.
   - **Network off mid-run**: retries after 1 s, 2 s and 4 s, then the GitHub card turns red.
   - **Fail 3 times, then recover**: one alert (banner, log, Slack if configured), then "recovered".
5. **Safe secrets (20 s).** GitHub card → **View details**: the config shows only `${github_token}`, and the secret sits in the vault with its age. `git check-ignore -v .env data/platform.db logs/platform.log` proves none of them are tracked.
6. **Roles (15 s).** Sign in as **viewer**: everything is readable, **Run now** and the ⋯ actions are locked, and Add integration and Audit log show "Admin only". Back as admin, **Audit log** shows who did what.
7. **Bonus (30 s).** **Actions & tickets**: high and critical incidents from Okta and GitHub open tickets in Jira `KAN` (KAN-6 came from the exfiltration guard). CVE feeds are intel, not tickets, and Dependabot alerts live on the Repositories page instead of flooding Jira.
   > "This is how INC-05 could have been caught."
