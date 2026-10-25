from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db import connect, migrate
from app.sessions import IDLE_TIMEOUT, create_session, delete_session, get_session
from app.users import create_user

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


@pytest.fixture
def uid(conn: sqlite3.Connection) -> str:
    return create_user(conn, "a@example.test", "correct horse battery", "analyst", NOW)


def test_idle_timeout_is_8_hours() -> None:
    assert timedelta(hours=8) == IDLE_TIMEOUT


def test_create_and_get(conn: sqlite3.Connection, uid: str) -> None:
    token, csrf = create_session(conn, uid, NOW)
    found = get_session(conn, token, NOW + timedelta(minutes=5))
    assert found is not None
    assert found.user.id == uid
    assert (found.user.email, found.user.role) == ("a@example.test", "analyst")
    assert found.csrf_token == csrf


def test_tokens_are_random_and_only_a_hash_is_stored(conn: sqlite3.Connection, uid: str) -> None:
    t1, c1 = create_session(conn, uid, NOW)
    t2, c2 = create_session(conn, uid, NOW)
    assert t1 != t2 and c1 != c2 and t1 != c1  # a new token on every login: no fixation
    assert len(t1) >= 43
    stored = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert hashlib.sha256(t1.encode()).hexdigest() in stored
    assert t1 not in stored


def test_unknown_or_empty_token(conn: sqlite3.Connection, uid: str) -> None:
    create_session(conn, uid, NOW)
    assert get_session(conn, "nope", NOW) is None
    assert get_session(conn, "", NOW) is None


def test_idle_expiry_and_sliding_window(conn: sqlite3.Connection, uid: str) -> None:
    token, _ = create_session(conn, uid, NOW)
    almost = NOW + IDLE_TIMEOUT - timedelta(seconds=1)
    assert get_session(conn, token, almost) is not None  # use extends it
    assert get_session(conn, token, almost + IDLE_TIMEOUT - timedelta(seconds=1)) is not None
    last_seen = almost + IDLE_TIMEOUT - timedelta(seconds=1)
    assert get_session(conn, token, last_seen + IDLE_TIMEOUT) is None


def test_expired_session_is_deleted(conn: sqlite3.Connection, uid: str) -> None:
    token, _ = create_session(conn, uid, NOW)
    assert get_session(conn, token, NOW + IDLE_TIMEOUT) is None
    assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_logout_invalidates(conn: sqlite3.Connection, uid: str) -> None:
    token, _ = create_session(conn, uid, NOW)
    delete_session(conn, token)
    assert get_session(conn, token, NOW) is None
    delete_session(conn, token)  # deleting twice is fine


def test_creating_a_session_purges_expired_ones(conn: sqlite3.Connection, uid: str) -> None:
    create_session(conn, uid, NOW)
    create_session(conn, uid, NOW + IDLE_TIMEOUT + timedelta(hours=1))
    assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 1
