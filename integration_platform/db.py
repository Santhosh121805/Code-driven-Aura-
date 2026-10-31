"""SQLite storage: one place for all results in the common schema (users, devices, events), plus runs, quarantine,
sync state, connector state, encrypted secrets and action bookkeeping."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from integration_platform.config import ENTITY_FIELDS, ROOT

SCHEMA_VERSION = 3
TABLES = {"user": "users", "device": "devices", "event": "events"}



def _entity_table(entity: str) -> str:
    cols = ",\n    ".join(f"{c} TEXT" for c in ENTITY_FIELDS[entity] if c != "id")
    ticket = "\n    ticket_key TEXT," if entity == "event" else ""
    return f"""
CREATE TABLE IF NOT EXISTS {TABLES[entity]} (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    stream TEXT NOT NULL,
    id TEXT NOT NULL,
    {cols},
    raw TEXT NOT NULL,{ticket}
    fetched_at TEXT NOT NULL,
    UNIQUE (source, id)
);"""


SCHEMA = "".join(_entity_table(e) for e in TABLES) + """
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp DESC);
CREATE TABLE IF NOT EXISTS integration_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    records_fetched INTEGER DEFAULT 0,
    records_new INTEGER DEFAULT 0,
    records_quarantined INTEGER DEFAULT 0,
    pages INTEGER DEFAULT 0,
    retries INTEGER DEFAULT 0,
    error TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_integration ON integration_runs (integration, id DESC);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    stream TEXT,
    entity TEXT,
    run_id INTEGER,
    reason TEXT NOT NULL,
    raw TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_source ON quarantine (source, id DESC);
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    ciphertext TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS connector_state (
    integration TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    detail TEXT,
    since TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_state (
    integration TEXT PRIMARY KEY,
    last_sync TEXT
);
CREATE TABLE IF NOT EXISTS failure_alerts (
    integration TEXT PRIMARY KEY,
    streak INTEGER NOT NULL DEFAULT 0,
    alerted_at TEXT,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    channels TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_dedupe (
    action TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    ticket_key TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (action, dedupe_key)
);
CREATE TABLE IF NOT EXISTS action_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    event_source TEXT,
    event_id TEXT,
    status TEXT NOT NULL,
    ticket_key TEXT,
    error TEXT,
    attempts INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);
"""
DATA_TABLES = ("users", "devices", "events", "integration_runs", "sync_state", "action_dedupe", "action_results",
               "quarantine", "connector_state", "failure_alerts", "notifications")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    """Thin thread-safe wrapper over one SQLite connection."""

    def __init__(self, path: str | Path | None = None):
        path = path or os.environ.get("PLATFORM_DB") or ROOT / "data" / "platform.db"
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            if self._conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
                # Older single-table layout: drop demo data tables (encrypted secrets are kept).
                for table in DATA_TABLES:
                    self._conn.execute(f"DROP TABLE IF EXISTS {table}")
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _exec(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def _one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        rows = self._all(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------ common-schema records
    def store(self, row: dict[str, Any]) -> str:
        """Store one normalised row. Events are immutable (insert once); users/devices are refreshed in place.
        Returns 'new', 'updated' or 'duplicate'. The (source, id) unique key guarantees no duplicates."""
        entity = row["entity"]
        table = TABLES[entity]
        cols = ["source", "stream", "id", *[c for c in ENTITY_FIELDS[entity] if c != "id"], "raw", "fetched_at"]
        values = [json.dumps(row["raw"], default=str) if c == "raw" else row.get(c) for c in cols]
        placeholders = ", ".join("?" * len(cols))
        with self._lock:
            exists = self._conn.execute(f"SELECT 1 FROM {table} WHERE source = ? AND id = ?", (row["source"], row["id"])).fetchone()
            if entity == "event":
                if exists:
                    return "duplicate"
                self._conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})", values)
            else:
                updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c not in ("source", "id"))
                self._conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
                                   f"ON CONFLICT(source, id) DO UPDATE SET {updates}", values)
            self._conn.commit()
        return "updated" if exists else "new"

    def list_records(self, entity: str, source: str | None = None, severity: str | None = None, type_: str | None = None,
                     limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
        table = TABLES[entity]
        where, params = [], []
        if source:
            where.append("source = ?"); params.append(source)
        if severity and entity == "event":
            where.append("severity = ?"); params.append(severity)
        if type_ and entity == "event":
            where.append("type = ?"); params.append(type_)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        order = {"event": "timestamp DESC, row_id DESC", "user": "fetched_at DESC, name", "device": "fetched_at DESC, hostname"}[entity]
        total = self._one(f"SELECT COUNT(*) AS n FROM {table} {clause}", params)["n"]
        rows = self._all(f"SELECT * FROM {table} {clause} ORDER BY {order} LIMIT ? OFFSET ?", params + [limit, offset])
        for row in rows:
            row["raw"] = json.loads(row["raw"])
        return rows, total

    def get_event(self, source: str, event_id: str) -> dict | None:
        row = self._one("SELECT * FROM events WHERE source = ? AND id = ?", (source, event_id))
        if row:
            row["raw"] = json.loads(row["raw"])
        return row

    def set_event_ticket(self, source: str, event_id: str, ticket_key: str) -> None:
        self._exec("UPDATE events SET ticket_key = ? WHERE source = ? AND id = ?", (ticket_key, source, event_id))

    def counts(self) -> dict[str, Any]:
        """Totals per entity and per source, plus event severities and ticket count."""
        out: dict[str, Any] = {}
        for entity, table in TABLES.items():
            by_src = {r["source"]: r["n"] for r in self._all(f"SELECT source, COUNT(*) AS n FROM {table} GROUP BY source")}
            out[table] = {"total": sum(by_src.values()), "by_source": by_src}
        out["by_severity"] = {r["severity"]: r["n"] for r in self._all("SELECT severity, COUNT(*) AS n FROM events GROUP BY severity")}
        out["tickets"] = self._one("SELECT COUNT(*) AS n FROM events WHERE ticket_key IS NOT NULL")["n"]
        return out

    def source_counts(self, source: str) -> dict[str, int]:
        return {table: self._one(f"SELECT COUNT(*) AS n FROM {table} WHERE source = ?", (source,))["n"] for table in TABLES.values()}

    # ------------------------------------------------------------ runs
    def start_run(self, integration: str) -> int:
        return self._exec("INSERT INTO integration_runs (integration, started_at, status) VALUES (?, ?, 'running')", (integration, utcnow())).lastrowid

    def finish_run(self, run_id: int, status: str, records_fetched: int, records_new: int, pages: int, retries: int, error: str | None,
                   quarantined: int = 0, detail: dict | None = None) -> None:
        self._exec(
            "UPDATE integration_runs SET finished_at=?, status=?, records_fetched=?, records_new=?, pages=?, retries=?, error=?, "
            "records_quarantined=?, detail=? WHERE id=?",
            (utcnow(), status, records_fetched, records_new, pages, retries, error, quarantined,
             json.dumps(detail) if detail else None, run_id),
        )

    def recent_runs(self, integration: str, limit: int = 10) -> list[dict]:
        rows = self._all("SELECT * FROM integration_runs WHERE integration = ? ORDER BY id DESC LIMIT ?", (integration, limit))
        for row in rows:
            row["detail"] = json.loads(row["detail"]) if row.get("detail") else None
        return rows

    def baseline_counts(self, integration: str, limit: int) -> list[int]:
        """records_fetched of the last `limit` successful runs (suspicious runs never pollute the baseline).
        Only runs after the latest human resume count: resuming accepts the new volume, so the baseline is re-learnt."""
        since = int(self.get_last_sync(f"guard_baseline_from:{integration}") or 0)
        rows = self._all("SELECT records_fetched FROM integration_runs WHERE integration = ? AND status = 'success' AND id > ? "
                         "ORDER BY id DESC LIMIT ?", (integration, since, limit))
        return [r["records_fetched"] for r in rows]

    def restart_baseline(self, integration: str) -> None:
        last = self._one("SELECT COALESCE(MAX(id), 0) AS id FROM integration_runs WHERE integration = ?", (integration,))
        self.set_last_sync(f"guard_baseline_from:{integration}", str(last["id"]))

    def run_totals(self, integration: str) -> dict[str, Any]:
        return self._one(
            "SELECT COUNT(*) AS runs, COALESCE(SUM(records_fetched),0) AS records_fetched, COALESCE(SUM(retries),0) AS retries, "
            "COALESCE(SUM(status='error'),0) AS errors FROM integration_runs WHERE integration = ?", (integration,))

    # ------------------------------------------------------------ connector state (suspicious / revoked)
    def set_state(self, integration: str, state: str, detail: dict | None = None) -> None:
        self._exec("INSERT INTO connector_state (integration, state, detail, since) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT(integration) DO UPDATE SET state = excluded.state, detail = excluded.detail, since = excluded.since",
                   (integration, state, json.dumps(detail) if detail else None, utcnow()))

    def get_state(self, integration: str) -> dict | None:
        row = self._one("SELECT * FROM connector_state WHERE integration = ?", (integration,))
        if row:
            row["detail"] = json.loads(row["detail"]) if row["detail"] else {}
        return row

    def clear_state(self, integration: str) -> None:
        self._exec("DELETE FROM connector_state WHERE integration = ?", (integration,))

    # ------------------------------------------------------------ repeated-failure alerting (B-4)
    def get_failure_state(self, integration: str) -> dict:
        return self._one("SELECT * FROM failure_alerts WHERE integration = ?", (integration,)) or {
            "integration": integration, "streak": 0, "alerted_at": None, "last_error": None}

    def set_failure_state(self, integration: str, streak: int, alerted_at: str | None, last_error: str | None) -> None:
        self._exec("INSERT INTO failure_alerts (integration, streak, alerted_at, last_error) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT(integration) DO UPDATE SET streak = excluded.streak, alerted_at = excluded.alerted_at, "
                   "last_error = excluded.last_error", (integration, streak, alerted_at, last_error))

    def add_notification(self, integration: str, kind: str, message: str, channels: list[str]) -> None:
        self._exec("INSERT INTO notifications (integration, kind, message, channels, created_at) VALUES (?, ?, ?, ?, ?)",
                   (integration, kind, message, json.dumps(channels), utcnow()))

    def list_notifications(self, limit: int = 20) -> list[dict]:
        rows = self._all("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            row["channels"] = json.loads(row["channels"])
        return rows

    # ------------------------------------------------------------ secrets (ciphertext only; see vault.py)
    def put_secret(self, name: str, ciphertext: str, created_at: str) -> None:
        self._exec("INSERT INTO secrets (name, ciphertext, created_at, revoked_at) VALUES (?, ?, ?, NULL) "
                   "ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, created_at = excluded.created_at, revoked_at = NULL",
                   (name, ciphertext, created_at))

    def get_secret(self, name: str) -> dict | None:
        return self._one("SELECT * FROM secrets WHERE name = ?", (name,))

    def list_secrets(self) -> list[dict]:
        return self._all("SELECT name, created_at, revoked_at FROM secrets ORDER BY name")

    def revoke_secret(self, name: str, at: str) -> None:
        """Wipe the ciphertext and leave a tombstone."""
        self._exec("INSERT INTO secrets (name, ciphertext, created_at, revoked_at) VALUES (?, NULL, ?, ?) "
                   "ON CONFLICT(name) DO UPDATE SET ciphertext = NULL, revoked_at = excluded.revoked_at", (name, at, at))

    def set_secret_created(self, name: str, created_at: str) -> None:
        self._exec("UPDATE secrets SET created_at = ? WHERE name = ?", (created_at, name))

    def delete_secret(self, name: str) -> None:
        self._exec("DELETE FROM secrets WHERE name = ?", (name,))

    def delete_revoked_secrets(self) -> None:
        self._exec("DELETE FROM secrets WHERE revoked_at IS NOT NULL")

    # ------------------------------------------------------------ quarantine
    def quarantine(self, source: str, run_id: int | None, record: Any, reason: str, stream: str | None = None,
                   entity: str | None = None) -> None:
        self._exec("INSERT INTO quarantine (source, stream, entity, run_id, reason, raw, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (source, stream, entity, run_id, reason, json.dumps(record, default=str), utcnow()))

    def list_quarantine(self, source: str, limit: int = 100) -> list[dict]:
        rows = self._all("SELECT * FROM quarantine WHERE source = ? ORDER BY id DESC LIMIT ?", (source, limit))
        for row in rows:
            row["raw"] = json.loads(row["raw"])
        return rows

    def quarantine_count(self, source: str) -> int:
        return self._one("SELECT COUNT(*) AS n FROM quarantine WHERE source = ?", (source,))["n"]

    # ------------------------------------------------------------ sync state (per integration stream)
    def get_last_sync(self, key: str) -> str | None:
        row = self._one("SELECT last_sync FROM sync_state WHERE integration = ?", (key,))
        return row["last_sync"] if row else None

    def set_last_sync(self, key: str, value: str) -> None:
        self._exec("INSERT INTO sync_state (integration, last_sync) VALUES (?, ?) ON CONFLICT(integration) DO UPDATE SET last_sync = excluded.last_sync", (key, value))

    # ------------------------------------------------------------ actions
    def claim_dedupe(self, action: str, dedupe_key: str) -> bool:
        """Atomically reserve a dedupe key. False means this action already fired (or is firing) for it."""
        with self._lock:
            try:
                self._conn.execute("INSERT INTO action_dedupe (action, dedupe_key, created_at) VALUES (?, ?, ?)", (action, dedupe_key, utcnow()))
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def complete_dedupe(self, action: str, dedupe_key: str, ticket_key: str | None) -> None:
        self._exec("UPDATE action_dedupe SET ticket_key = ? WHERE action = ? AND dedupe_key = ?", (ticket_key, action, dedupe_key))

    def add_action_result(self, action: str, dedupe_key: str, source: str, event_id: str, status: str,
                          ticket_key: str | None, error: str | None, attempts: int) -> None:
        self._exec(
            "INSERT INTO action_results (action, dedupe_key, event_source, event_id, status, ticket_key, error, attempts, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (action, dedupe_key, source, event_id, status, ticket_key, error, attempts, utcnow()),
        )

    def list_action_results(self, action: str | None = None, limit: int = 50) -> list[dict]:
        if action:
            return self._all("SELECT * FROM action_results WHERE action = ? ORDER BY id DESC LIMIT ?", (action, limit))
        return self._all("SELECT * FROM action_results ORDER BY id DESC LIMIT ?", (limit,))

    def action_stats(self, action: str) -> dict[str, Any]:
        return self._one("SELECT COALESCE(SUM(status='success'),0) AS success, COALESCE(SUM(status='failed'),0) AS failed FROM action_results WHERE action = ?", (action,))

    # ------------------------------------------------------------ demo
    def reset(self) -> None:
        """Clear the demo data. Ticket claims and results stay: the tickets themselves live in the real Jira."""
        with self._lock:
            for table in DATA_TABLES:
                if table not in ("action_dedupe", "action_results"):
                    self._conn.execute(f"DELETE FROM {table}")
            self._conn.commit()
