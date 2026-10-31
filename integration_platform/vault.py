"""Secrets at rest: a Fernet-encrypted vault in SQLite, with secret age tracking and revocation.

Configs still only contain ${NAME} references. Resolution order: vault -> environment (.env).
A revoked secret leaves a tombstone, so the environment fallback can no longer resurrect it.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from integration_platform import config, logmask
from integration_platform.config import ENV_REF_ANY, IntegrationConfig, MissingSecretError

log = logging.getLogger("vault")


def ensure_secrets_key(env_file: Path) -> str:
    """Return SECRETS_KEY, generating one into .env on first run."""
    key = os.environ.get("SECRETS_KEY", "").strip()
    if key:
        return key
    key = Fernet.generate_key().decode()
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    if any(line.startswith("SECRETS_KEY=") for line in lines):
        lines = [f"SECRETS_KEY={key}" if line.startswith("SECRETS_KEY=") else line for line in lines]
    else:
        lines += ["", "# Master key for the encrypted secret vault (generated on first run - keep it safe)", f"SECRETS_KEY={key}"]
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.environ["SECRETS_KEY"] = key
    log.info("generated a new SECRETS_KEY in %s", env_file)
    return key


def parse_age_overrides(text: str | None) -> dict[str, int]:
    """'NAME:95,OTHER:10' -> {'NAME': 95, 'OTHER': 10} (demo helper to make a seeded secret look old)."""
    out: dict[str, int] = {}
    for part in (text or "").split(","):
        name, _, days = part.strip().partition(":")
        if name and days.strip().isdigit():
            out[name.strip()] = int(days)
    return out


def secret_refs(cfg: Any) -> list[str]:
    """Names of all ${VAR} references in a connector's (or action's) auth and headers."""
    auth = getattr(cfg, "auth", None) or cfg.request.auth  # actions keep auth under request
    values = [v for v in auth.model_dump().values() if isinstance(v, str)]
    values += list(getattr(cfg, "headers", {}).values())
    values += list(getattr(getattr(cfg, "request", None), "headers", {}).values())
    if getattr(cfg, "auth", None) is None:
        values.append(cfg.request.base_url)  # an action's target URL can itself be a secret (Slack webhook)
    return sorted({m.group(1) for v in values for m in ENV_REF_ANY.finditer(v)})


class Vault:
    def __init__(self, db: Any, key: str):
        self.db = db
        self.fernet = Fernet(key.encode() if isinstance(key, str) else key)

    # ---------------------------------------------------------------- storage
    def set(self, name: str, value: str, created_at: datetime | None = None) -> None:
        created = (created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.db.put_secret(name, self.fernet.encrypt(value.encode()).decode(), created)

    def get(self, name: str) -> str | None:
        """Decrypted value, None if not in the vault. Raises MissingSecretError if the secret was revoked."""
        row = self.db.get_secret(name)
        if row is None:
            return None
        if row["revoked_at"]:
            raise MissingSecretError(f"Secret {name} was revoked at {row['revoked_at']}; store a new value to re-enable")
        try:
            value = self.fernet.decrypt(row["ciphertext"].encode()).decode()
        except InvalidToken:
            log.warning("secret %s cannot be decrypted with the current SECRETS_KEY; ignoring the stored copy", name)
            return None
        logmask.remember(value)
        return value

    def info(self, name: str) -> dict[str, Any]:
        row = self.db.get_secret(name)
        if row is None:
            return {"name": name, "in_vault": False, "age_days": None, "revoked": False}
        age = (datetime.now(timezone.utc) - datetime.strptime(row["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).days
        return {"name": name, "in_vault": True, "created_at": row["created_at"], "age_days": age, "revoked": bool(row["revoked_at"])}

    def revoke(self, name: str) -> None:
        self.db.revoke_secret(name, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    # ---------------------------------------------------------------- bootstrap
    def import_from_env(self, names: list[str], age_overrides: dict[str, int] | None = None) -> list[str]:
        """Encrypt referenced secrets found in the environment into the vault (once). Returns imported names."""
        imported = []
        for name in names:
            row = self.db.get_secret(name)
            if row is not None and (row["revoked_at"] or self._decryptable(row)):
                continue
            value = os.environ.get(name)
            if not value:
                continue
            days = (age_overrides or {}).get(name, 0)
            self.set(name, value, datetime.now(timezone.utc) - timedelta(days=days))
            imported.append(name)
        return imported

    def _decryptable(self, row: dict) -> bool:
        try:
            self.fernet.decrypt(row["ciphertext"].encode())
            return True
        except (InvalidToken, AttributeError):
            return False

    def set_age(self, name: str, days: int) -> None:
        """Demo helper: backdate an existing secret so 'Rotate secret' shows (SECRET_AGE_OVERRIDES on Reset demo)."""
        if self.db.get_secret(name):
            self.db.set_secret_created(name, (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def lookup(self, name: str) -> str | None:
        """Hook for config.resolve_env."""
        return self.get(name)

    def activate(self) -> None:
        config.set_secret_lookup(self.lookup)


def connector_secret_status(cfg: IntegrationConfig, vault: Vault | None) -> list[dict[str, Any]]:
    """Per referenced secret: age and whether it is past the connector's rotation policy."""
    out = []
    for name in secret_refs(cfg):
        info = vault.info(name) if vault else {"name": name, "in_vault": False, "age_days": None, "revoked": False}
        info["rotate"] = info["age_days"] is not None and info["age_days"] > cfg.secret_max_age_days
        info["max_age_days"] = cfg.secret_max_age_days
        out.append(info)
    return out
