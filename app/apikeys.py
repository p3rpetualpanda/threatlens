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


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_api_key(conn: sqlite3.Connection, name: str, now: datetime) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO api_keys (id, name, token_hash, scope, created_at) VALUES (?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), name, _hash(token), "ingest", now.isoformat()],
    )
    conn.commit()
    return token


def check_api_key(conn: sqlite3.Connection, token: str, scope: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM api_keys WHERE token_hash = ? AND scope = ? AND revoked_at IS NULL",
        [_hash(token), scope],
    ).fetchone()
    return row is not None


def revoke_api_key(conn: sqlite3.Connection, key_id: str, now: datetime) -> None:
    """Revoke a key; a second revoke keeps the first time. Unknown id raises KeyError."""
    if conn.execute("SELECT 1 FROM api_keys WHERE id = ?", [key_id]).fetchone() is None:
        raise KeyError(key_id)
    conn.execute(
        "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        [now.isoformat(), key_id],
    )
    conn.commit()
