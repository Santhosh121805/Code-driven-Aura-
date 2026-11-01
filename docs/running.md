# Running PlugSec

Install, first run, the pages, demo sign-in modes, roles and the audit log.

[← Back to the docs index](README.md)

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

For a live demo, `DEMO_OPEN_SIGNIN=on` in `.env` accepts **any** username and password and gives the role picked on the card (roles and the audit log still apply; the audit entry reads "Signed in (open demo sign-in)"). Anyone who can open the page can then become admin, so remove it after the demo.

Set `DEMO_MODE=on` in `.env` to let the sign-in card pre-fill the username for the picked role and show "Demo accounts are configured in .env". Passwords are never shown, and the role always comes from the account on the server, not from the picked tab.

Tests: `python -m pytest`. There are 295 tests; they are hermetic and never read your `.env` or call real APIs.


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
