"""Scan history in SQLite (swap for Postgres when you need multiple workers).

Reports are addressed by a random token, not the row id, so on a public
deployment nobody can enumerate other people's scans by counting upwards.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    grade       TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    result_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


def _path() -> str:
    return os.environ.get("VIGIL_DB", "vigil.db")


def _retention_days() -> int:
    return int(os.environ.get("VIGIL_RETENTION_DAYS", "30"))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
    if "token" not in cols:  # migrate databases created before report tokens existed
        conn.execute("ALTER TABLE scans ADD COLUMN token TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_token ON scans(token)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
    return conn


def save(result: dict) -> str:
    """Store a scan, prune expired ones, and return the report token."""
    token = secrets.token_urlsafe(16)
    cutoff = (datetime.now(UTC) - timedelta(days=_retention_days())).isoformat(timespec="seconds")
    with closing(connect()) as conn, conn:
        conn.execute(
            "INSERT INTO scans (token, target, score, grade, created_at, result_json) VALUES (?, ?, ?, ?, ?, ?)",
            (token, result["final_url"], result["score"], result["grade"], result["started_at"],
             json.dumps(result)),
        )
        conn.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))
    return token


def get(token: str) -> dict | None:
    with closing(connect()) as conn:
        row = conn.execute("SELECT token, result_json FROM scans WHERE token = ?", (token,)).fetchone()
    if row is None:
        return None
    return {"id": row["token"], **json.loads(row["result_json"])}
