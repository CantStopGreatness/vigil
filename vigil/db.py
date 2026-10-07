"""Scan history: SQLite locally, Upstash Redis when its credentials are set (e.g. on Vercel,
which has no persistent disk and runs many instances).

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

import httpx

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


def _redis() -> tuple[str, str] | None:
    """Upstash REST credentials, under either the Vercel KV or the Upstash variable names."""
    url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    return (url, token) if url and token else None


def _redis_cmd(*args: str | int):
    url, token = _redis()
    r = httpx.post(url, json=[str(a) for a in args], headers={"Authorization": f"Bearer {token}"}, timeout=10)
    r.raise_for_status()
    return r.json()["result"]


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
    if _redis():  # Redis expires the key itself, so there's nothing to prune
        _redis_cmd("SET", f"vigil:scan:{token}", json.dumps(result), "EX", _retention_days() * 86400)
        return token
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
    if _redis():
        raw = _redis_cmd("GET", f"vigil:scan:{token}")
        return None if raw is None else {"id": token, **json.loads(raw)}
    with closing(connect()) as conn:
        row = conn.execute("SELECT token, result_json FROM scans WHERE token = ?", (token,)).fetchone()
    if row is None:
        return None
    return {"id": row["token"], **json.loads(row["result_json"])}
