"""Login throttle: 5 failures per 15 minutes, counted per username and per IP.

Unknown usernames are counted too, so the lock never reveals whether an account exists.
shortcut: a locked username can be used to lock a victim out for 15 minutes; accepted, and
listed in the threat model. The IP key is the socket peer address, so behind a proxy it needs
the proxy's forwarded address.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

MAX_FAILURES = 5
WINDOW = timedelta(minutes=15)


def keys_for(email: str, ip: str) -> list[str]:
    return [f"user:{email.strip().lower()}", f"ip:{ip}"]


def is_locked(conn: sqlite3.Connection, keys: list[str], now: datetime) -> bool:
    since = (now - WINDOW).isoformat()
    for key in keys:
        count = conn.execute(
            "SELECT count(*) FROM login_attempts WHERE key = ? AND at > ?", [key, since]
        ).fetchone()[0]
        if count >= MAX_FAILURES:
            return True
    return False


def record_failure(conn: sqlite3.Connection, keys: list[str], now: datetime) -> None:
    conn.execute("DELETE FROM login_attempts WHERE at <= ?", [(now - WINDOW).isoformat()])
    conn.executemany(
        "INSERT INTO login_attempts (key, at) VALUES (?, ?)", [(k, now.isoformat()) for k in keys]
    )
    conn.commit()


def clear(conn: sqlite3.Connection, key: str) -> None:
    """Forget a key's failures after a good login. Used for the username, never the IP."""
    conn.execute("DELETE FROM login_attempts WHERE key = ?", [key])
    conn.commit()
