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


def reserve(conn: sqlite3.Connection, keys: list[str], now: datetime) -> list[int] | None:
    """Count this attempt as a failure *before* the password is checked, or return None if locked.

    The write lock makes check-and-insert one step, so parallel guesses cannot all see a count
    of zero. A good login hands the row ids back to `forgive`.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM login_attempts WHERE at <= ?", [(now - WINDOW).isoformat()])
        if is_locked(conn, keys, now):
            conn.commit()
            return None
        ids = [
            conn.execute(
                "INSERT INTO login_attempts (key, at) VALUES (?, ?)", [k, now.isoformat()]
            ).lastrowid
            for k in keys
        ]
    except BaseException:
        conn.rollback()
        raise
    conn.commit()
    return [int(i) for i in ids if i is not None]


def note_failure(conn: sqlite3.Connection, key: str, now: datetime) -> None:
    """Count one failure for `key` without checking the limit (the ingest key throttle)."""
    conn.execute("DELETE FROM login_attempts WHERE at <= ?", [(now - WINDOW).isoformat()])
    conn.execute("INSERT INTO login_attempts (key, at) VALUES (?, ?)", [key, now.isoformat()])
    conn.commit()


def forgive(conn: sqlite3.Connection, user_key: str, attempt_ids: list[int]) -> None:
    """After a good login: drop the username's failures and this attempt's own rows.

    The IP's earlier failures stay. Does not commit: the caller commits with the session.
    """
    conn.execute("DELETE FROM login_attempts WHERE key = ?", [user_key])
    conn.executemany("DELETE FROM login_attempts WHERE id = ?", [(i,) for i in attempt_ids])


def tipped_over(
    conn: sqlite3.Connection, keys: list[str], attempt_ids: list[int], now: datetime
) -> bool:
    """True if this attempt's own row is the one that reached the limit for some key.

    Unlike `is_locked`, two attempts that fail at the same moment cannot both answer yes.
    """
    since = (now - WINDOW).isoformat()
    return any(
        conn.execute(
            "SELECT count(*) FROM login_attempts WHERE key = ? AND at > ? AND id <= ?",
            [key, since, attempt_id],
        ).fetchone()[0]
        == MAX_FAILURES
        for key, attempt_id in zip(keys, attempt_ids, strict=True)
    )
