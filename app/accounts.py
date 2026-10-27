"""Admin changes to accounts: role, disable, enable. Every change is audited.

Rules: only an admin; never your own account; the last active admin stays. The actor's role is
re-read inside the write transaction (the session object may be stale), so the actor is always
a second active admin and the last one can never be removed.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime

from .audit import record
from .users import ROLES, User


class AccountError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


def _target(conn: sqlite3.Connection, actor: User, user_id: str) -> sqlite3.Row:
    current = conn.execute(
        "SELECT role, disabled_at FROM users WHERE id = ?", [actor.id]
    ).fetchone()
    if current is None or current["role"] != "admin" or current["disabled_at"] is not None:
        raise AccountError(403, "only an admin can change accounts")
    if user_id == actor.id:
        raise AccountError(403, "you cannot change your own account")
    row: sqlite3.Row | None = conn.execute(
        "SELECT id, email, role FROM users WHERE id = ?", [user_id]
    ).fetchone()
    if row is None:
        raise AccountError(404, "no such user")
    return row


def _write(conn: sqlite3.Connection, do: Callable[[], None]) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        do()
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def change_role(
    conn: sqlite3.Connection, actor: User, user_id: str, role: str, now: datetime
) -> None:
    def run() -> None:
        target = _target(conn, actor, user_id)
        if role not in ROLES:
            raise AccountError(422, f"role must be one of {', '.join(ROLES)}")
        if role == target["role"]:
            return
        conn.execute("UPDATE users SET role = ? WHERE id = ?", [role, user_id])
        detail = {"email": target["email"], "from": target["role"], "to": role}
        record(conn, actor.email, "user.role", user_id, detail, now)

    _write(conn, run)


def set_disabled(
    conn: sqlite3.Connection, actor: User, user_id: str, disabled: bool, now: datetime
) -> None:
    def run() -> None:
        target = _target(conn, actor, user_id)
        if disabled:
            conn.execute(
                "UPDATE users SET disabled_at = ? WHERE id = ?", [now.isoformat(), user_id]
            )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
        else:
            conn.execute("UPDATE users SET disabled_at = NULL WHERE id = ?", [user_id])
        action = "user.disable" if disabled else "user.enable"
        record(conn, actor.email, action, user_id, {"email": target["email"]}, now)

    _write(conn, run)
