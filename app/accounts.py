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
from .lockout import forgive, reserve
from .sessions import end_other_sessions
from .users import ROLES, User, authenticate, hash_password


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


_OPERATOR_ACTIONS = {
    "disable": "user.disable",
    "enable": "user.enable",
    "revoke-sessions": "user.sessions_revoked",
}


def operator_change(conn: sqlite3.Connection, email: str, action: str, now: datetime) -> None:
    """`threatlens user ...`: whoever holds the database file may do this, so no role checks,
    no last-admin rule. disable and revoke-sessions end every session of the user."""

    def run() -> None:
        row = conn.execute(
            "SELECT id, email FROM users WHERE email = ?", [email.strip().lower()]
        ).fetchone()
        if row is None:
            raise AccountError(404, "no such user")
        if action == "enable":
            conn.execute("UPDATE users SET disabled_at = NULL WHERE id = ?", [row["id"]])
        else:
            if action == "disable":
                conn.execute(
                    "UPDATE users SET disabled_at = ? WHERE id = ?", [now.isoformat(), row["id"]]
                )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", [row["id"]])
        record(conn, "cli", _OPERATOR_ACTIONS[action], row["id"], {"email": row["email"]}, now)

    _write(conn, run)


def operator_set_password(
    conn: sqlite3.Connection, email: str, password: str, now: datetime
) -> None:
    """`threatlens user set-password`: replace the hash and end every session of the user."""
    try:
        new_hash = hash_password(password)
    except ValueError as exc:
        raise AccountError(422, str(exc)) from exc

    def run() -> None:
        row = conn.execute(
            "SELECT id, email FROM users WHERE email = ?", [email.strip().lower()]
        ).fetchone()
        if row is None:
            raise AccountError(404, "no such user")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", [new_hash, row["id"]])
        conn.execute("DELETE FROM sessions WHERE user_id = ?", [row["id"]])
        record(conn, "cli", "user.password_set", row["id"], {"email": row["email"]}, now)

    _write(conn, run)


def change_own_password(
    conn: sqlite3.Connection, user: User, current: str, new: str, keep_token: str, now: datetime
) -> None:
    """The signed-in user changes their own password. Wrong guesses of the current password
    count against the same 15-minute limit as logins, so a stolen session cannot be used to
    guess it. Every other session of the user ends; the one in `keep_token` stays."""
    keys = [f"pw:{user.id}"]
    attempt = reserve(conn, keys, now)
    if attempt is None:
        raise AccountError(429, "too many wrong passwords, try again later")
    if authenticate(conn, user.email, current) is None:
        raise AccountError(403, "the current password is wrong")
    try:
        new_hash = hash_password(new)
    except ValueError as exc:
        raise AccountError(422, str(exc)) from exc

    def run() -> None:
        forgive(conn, keys[0], attempt)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", [new_hash, user.id])
        end_other_sessions(conn, user.id, keep_token)
        record(conn, user.email, "user.password_changed", user.id, {}, now)

    _write(conn, run)


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
