"""Server-side sessions. The cookie holds a random token; only its sha256 is stored.

Idle expiry is sliding: every use pushes `expires_at` out by IDLE_TIMEOUT, but a session
never outlives ABSOLUTE_TIMEOUT after login. Each session also
carries a CSRF synchronizer token (spec §6.4). Logging in always makes a new session, so a
token planted before login is never promoted.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from .users import User

IDLE_TIMEOUT = timedelta(hours=8)
ABSOLUTE_TIMEOUT = timedelta(hours=24)  # a stolen cookie cannot be kept alive forever


@dataclass(frozen=True)
class Session:
    user: User
    csrf_token: str


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    conn: sqlite3.Connection, user_id: str, now: datetime, commit: bool = True
) -> tuple[str, str]:
    """Return (session token, csrf token). Both are shown only here."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", [now.isoformat()])
    conn.execute(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, csrf_token) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            str(uuid.uuid4()),
            user_id,
            _hash(token),
            (now + IDLE_TIMEOUT).isoformat(),
            now.isoformat(),
            csrf,
        ],
    )
    if commit:
        conn.commit()
    return token, csrf


def get_session(conn: sqlite3.Connection, token: str, now: datetime) -> Session | None:
    """Return the live session for the token and extend it, or None."""
    row = conn.execute(
        "SELECT s.id, s.expires_at, s.created_at, s.csrf_token, u.id AS uid, u.email, u.role "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        [_hash(token)],
    ).fetchone()
    if row is None:
        return None
    # ISO-8601 strings in one fixed format (UTC, same offset) compare in time order.
    too_old = datetime.fromisoformat(row["created_at"]) + ABSOLUTE_TIMEOUT <= now
    if too_old or row["expires_at"] <= now.isoformat():
        conn.execute("DELETE FROM sessions WHERE id = ?", [row["id"]])
        conn.commit()
        return None
    conn.execute(
        "UPDATE sessions SET expires_at = ? WHERE id = ?",
        [(now + IDLE_TIMEOUT).isoformat(), row["id"]],
    )
    conn.commit()
    return Session(User(row["uid"], row["email"], row["role"]), row["csrf_token"])


def delete_session(conn: sqlite3.Connection, token: str, commit: bool = True) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", [_hash(token)])
    if commit:
        conn.commit()
