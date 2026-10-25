"""Analyst accounts: argon2id password hashes, lower-cased unique emails, four roles."""

from __future__ import annotations

import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .audit import record

ROLES = ("viewer", "analyst", "lead", "admin")  # each role includes the ones before it
MIN_PASSWORD = 12

_hasher = PasswordHasher()  # argon2id with the library's current default cost
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
# Verified against when the email is unknown, so a missing account costs the same time.
_DUMMY_HASH = _hasher.hash("not-a-real-password")


@dataclass(frozen=True)
class User:
    id: str
    email: str
    role: str


def create_user(
    conn: sqlite3.Connection,
    email: str,
    password: str,
    role: str,
    now: datetime,
    actor: str = "system",
) -> str:
    email = email.strip().lower()
    if not _EMAIL.fullmatch(email):
        raise ValueError("email is not valid")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    user_id = str(uuid.uuid4())
    try:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            [user_id, email, _hasher.hash(password), role, now.isoformat()],
        )
        record(conn, actor, "user.create", user_id, {"email": email, "role": role}, now)
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError(f"a user with email {email} already exists") from exc
    except BaseException:
        conn.rollback()
        raise
    return user_id


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> User | None:
    """Return the user if the password matches, else None (same answer for unknown email)."""
    row = conn.execute(
        "SELECT id, email, role, password_hash FROM users WHERE email = ?",
        [email.strip().lower()],
    ).fetchone()
    try:
        _hasher.verify(_DUMMY_HASH if row is None else row["password_hash"], password)
    except (VerificationError, InvalidHashError):
        return None
    if row is None:
        return None
    return User(row["id"], row["email"], row["role"])
