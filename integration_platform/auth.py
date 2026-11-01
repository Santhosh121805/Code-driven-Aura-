"""Sign-in, roles and the rules for who may call what. viewer < analyst < admin.

Users live in .env as PLUGSEC_USERS="name:role:scrypt$salt$hash,..." (passwords are only ever stored hashed).
Sessions are stateless HMAC-signed cookies keyed from SECRETS_KEY, so they survive restarts but not a key change.

Set or reset a password:  python -m integration_platform.auth set-password <user> <role>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import defaultdict, deque

ROLES = ("viewer", "analyst", "admin")
RANK = {role: i for i, role in enumerate(ROLES)}
COOKIE = "plugsec_session"
SESSION_SECONDS = 12 * 3600
USERS_ENV = "PLUGSEC_USERS"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}

# Analysts may run connectors; anything else that changes state, calls a tool with stored secrets
# (wizard test / sample / AI suggest) or exposes secret metadata is admin only. Reads are open to every role.
ANALYST_WRITES = [re.compile(r"^/api/integrations/[^/]+/run$")]
ADMIN_READS = [re.compile(r"^/api/audit$"), re.compile(r"^/api/secrets$")]


# ------------------------------------------------------------------ passwords
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    return f"scrypt${_b64(salt)}${_b64(hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT))}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        return hmac.compare_digest(hash_password(password, _unb64(salt)).split("$")[2], digest)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))  # unknown users cost the same time as known ones


def load_users(value: str | None = None) -> dict[str, tuple[str, str]]:
    """{name: (role, password hash)} from PLUGSEC_USERS (or `value`); malformed entries are ignored."""
    users = {}
    for entry in ((os.environ.get(USERS_ENV) or "") if value is None else value).split(","):
        parts = entry.strip().split(":", 2)
        if len(parts) == 3 and parts[1] in RANK and parts[2].startswith("scrypt$"):
            users[parts[0]] = (parts[1], parts[2])
    return users


def authenticate(username: str, password: str) -> str | None:
    """The user's role if the password matches, else None."""
    role, stored = load_users().get(username, (None, _DUMMY_HASH))
    ok = verify_password(password, stored)
    return role if ok and role else None


# ------------------------------------------------------------------ sessions
_FALLBACK_KEY = os.urandom(32)  # no SECRETS_KEY (tests): sessions last for this process only


def _key() -> bytes:
    master = os.environ.get("SECRETS_KEY")
    return hmac.new(master.encode(), b"plugsec-session-v1", hashlib.sha256).digest() if master else _FALLBACK_KEY


def issue_session(username: str, role: str, now: float | None = None) -> str:
    payload = _b64(json.dumps({"u": username, "r": role, "exp": int((now or time.time()) + SESSION_SECONDS)}).encode())
    return f"{payload}.{_b64(hmac.new(_key(), payload.encode(), hashlib.sha256).digest())}"


def read_session(token: str | None, now: float | None = None) -> dict[str, str] | None:
    """{"user", "role"} for a valid, unexpired session whose user still exists with that role."""
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(_b64(hmac.new(_key(), payload.encode(), hashlib.sha256).digest()), sig):
        return None
    try:
        data = json.loads(_unb64(payload))
    except ValueError:
        return None
    if data.get("exp", 0) < (now or time.time()):
        return None
    current = load_users().get(data.get("u"))
    if (not current or current[0] != data.get("r")) and not (open_signin() and data.get("r") in ROLES):
        return None  # user removed or role changed: sign in again (open demo sign-in has no accounts to check)
    return {"user": data["u"], "role": data["r"]}


# ------------------------------------------------------------------ authorisation
def required_role(method: str, path: str) -> str:
    if method in ("GET", "HEAD"):
        return "admin" if any(p.match(path) for p in ADMIN_READS) else "viewer"
    return "analyst" if any(p.match(path) for p in ANALYST_WRITES) else "admin"


def allowed(role: str, needed: str) -> bool:
    return RANK.get(role, -1) >= RANK[needed]


# ------------------------------------------------------------------ brute-force cooldown
# 5 failures for one username from one address -> 30 s cooldown for that pair. A wider per-address budget stops
# cycling through usernames. A successful sign-in clears the pair.
MAX_FAILURES, COOLDOWN_SECONDS, MAX_FAILURES_PER_ADDRESS = 5, 30, 20
_failures: dict[str, deque] = defaultdict(deque)


def _keys(client: str, username: str) -> list[tuple[str, int]]:
    return [(f"user:{client}|{username.strip().lower()}", MAX_FAILURES), (f"addr:{client}", MAX_FAILURES_PER_ADDRESS)]


def cooldown_left(client: str, username: str, now: float | None = None) -> int:
    """Seconds until this username/address may try again (0 = allowed)."""
    now = now or time.time()
    left = 0.0
    for key, limit in _keys(client, username):
        recent = _failures[key]
        while recent and recent[0] < now - COOLDOWN_SECONDS - 60:  # forget old attempts
            recent.popleft()
        if len(recent) >= limit:
            left = max(left, recent[-1] + COOLDOWN_SECONDS - now)
            if recent[-1] + COOLDOWN_SECONDS <= now:
                recent.clear()  # cooldown served: a fresh budget
    return int(left + 0.999) if left > 0 else 0


def note_failure(client: str, username: str, now: float | None = None) -> None:
    for key, _ in _keys(client, username):
        _failures[key].append(now or time.time())


def clear_failures(client: str, username: str) -> None:
    _failures.pop(_keys(client, username)[0][0], None)


# ------------------------------------------------------------------ demo hint for the public sign-in card
def demo_mode() -> bool:
    return (os.environ.get("DEMO_MODE") or "").strip().lower() in ("on", "1", "true", "yes")


def open_signin() -> bool:
    """DEMO_OPEN_SIGNIN=on: any username / password signs in, with the role picked on the card. For live demos only:
    roles and the audit log still apply, but anyone who can reach the page can become admin."""
    return (os.environ.get("DEMO_OPEN_SIGNIN") or "").strip().lower() in ("on", "1", "true", "yes")


def demo_usernames() -> dict[str, str]:
    """First account per role, used only to pre-fill the username field in demo mode. Never passwords."""
    out: dict[str, str] = {}
    for name, (role, _) in load_users().items():
        out.setdefault(role, name)
    return out


# ------------------------------------------------------------------ CLI
def _set_password(env_file: str, username: str, role: str, password: str) -> None:
    users = {name: f"{name}:{r}:{h}" for name, (r, h) in _users_in_file(env_file).items()}
    users[username] = f"{username}:{role}:{hash_password(password)}"
    _write_users(env_file, ",".join(users.values()))


def _users_in_file(env_file: str) -> dict[str, tuple[str, str]]:
    lines = open(env_file, encoding="utf-8").read().splitlines()
    return load_users(next((line.split("=", 1)[1] for line in lines if line.startswith(f"{USERS_ENV}=")), ""))


def _write_users(env_file: str, value: str) -> None:
    lines = open(env_file, encoding="utf-8").read().splitlines()
    if any(line.startswith(f"{USERS_ENV}=") for line in lines):
        lines = [f"{USERS_ENV}={value}" if line.startswith(f"{USERS_ENV}=") else line for line in lines]
    else:
        lines += ["", "# Dashboard sign-in (scrypt hashes). Change with: python -m integration_platform.auth set-password <user> <role>",
                  f"{USERS_ENV}={value}"]
    with open(env_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def ensure_default_users(env_file: str) -> dict[str, str]:
    """First run: create admin / analyst / viewer with random passwords. Returns {user: password} for the ones created."""
    if _users_in_file(env_file):
        return {}
    created = {role: secrets.token_urlsafe(9) for role in ("admin", "analyst", "viewer")}
    _write_users(env_file, ",".join(f"{role}:{role}:{hash_password(pw)}" for role, pw in created.items()))
    return created


if __name__ == "__main__":
    import argparse
    import getpass
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Manage dashboard users in .env")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("set-password", help="create a user or change a password / role")
    sp.add_argument("user")
    sp.add_argument("role", choices=ROLES)
    args = parser.parse_args()
    pw = getpass.getpass(f"New password for {args.user}: ")
    if len(pw) < 8 or pw != getpass.getpass("Repeat: "):
        raise SystemExit("Passwords must match and be at least 8 characters.")
    _set_password(str(Path(__file__).resolve().parent.parent / ".env"), args.user, args.role, pw)
    print(f"Saved {args.user} ({args.role}). Restart the platform to apply.")
