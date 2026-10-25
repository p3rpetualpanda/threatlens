"""Ingest API keys. Only a sha256 of the token is stored; the token is shown once at creation.

The token is 256 bits of randomness, so a fast unsalted hash is enough, and lookup is by hash
(an indexed equality match), never a string compare against the secret.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import uuid
from datetime import datetime

from .audit import record


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_api_key(
    conn: sqlite3.Connection, name: str, now: datetime, actor: str = "system"
) -> str:
    token = secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    try:
        conn.execute(
            "INSERT INTO api_keys (id, name, token_hash, scope, created_at) VALUES (?, ?, ?, ?, ?)",
            [key_id, name, _hash(token), "ingest", now.isoformat()],
        )
        record(conn, actor, "api_key.create", key_id, {"name": name, "scope": "ingest"}, now)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return token


def lookup_api_key(conn: sqlite3.Connection, token: str, scope: str) -> str | None:
    """Return the key's id if the token is valid for the scope and not revoked."""
    row = conn.execute(
        "SELECT id FROM api_keys WHERE token_hash = ? AND scope = ? AND revoked_at IS NULL",
        [_hash(token), scope],
    ).fetchone()
    return None if row is None else str(row[0])


def check_api_key(conn: sqlite3.Connection, token: str, scope: str) -> bool:
    return lookup_api_key(conn, token, scope) is not None


def revoke_api_key(
    conn: sqlite3.Connection, key_id: str, now: datetime, actor: str = "system"
) -> None:
    """Revoke a key; a second revoke keeps the first time. Unknown id raises KeyError."""
    if conn.execute("SELECT 1 FROM api_keys WHERE id = ?", [key_id]).fetchone() is None:
        raise KeyError(key_id)
    try:
        changed = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            [now.isoformat(), key_id],
        ).rowcount
        if changed:  # a repeat revoke changes nothing, so it leaves no audit row
            record(conn, actor, "api_key.revoke", key_id, None, now)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
