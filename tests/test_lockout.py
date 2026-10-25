from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db import connect, migrate
from app.lockout import MAX_FAILURES, WINDOW, forgive, is_locked, keys_for, reserve

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
KEYS = keys_for("Ana@Example.test", "198.51.100.7")


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def _fail(conn: sqlite3.Connection, n: int, keys: list[str] = KEYS, at: datetime = NOW) -> None:
    for _ in range(n):
        reserve(conn, keys, at)


def test_limits_are_5_per_15_minutes() -> None:
    assert (5, timedelta(minutes=15)) == (MAX_FAILURES, WINDOW)


def test_keys_normalise_the_email() -> None:
    assert keys_for("  ANA@Example.test ", "198.51.100.7") == [
        "user:ana@example.test",
        "ip:198.51.100.7",
    ]


def test_locked_after_five_failures_not_four(conn: sqlite3.Connection) -> None:
    _fail(conn, 4)
    assert not is_locked(conn, KEYS, NOW)
    _fail(conn, 1)
    assert is_locked(conn, KEYS, NOW)


def test_lock_lifts_after_the_window(conn: sqlite3.Connection) -> None:
    _fail(conn, 5)
    assert is_locked(conn, KEYS, NOW + WINDOW - timedelta(seconds=1))
    assert not is_locked(conn, KEYS, NOW + WINDOW)


def test_username_lock_holds_from_a_new_ip(conn: sqlite3.Connection) -> None:
    _fail(conn, 5)
    assert is_locked(conn, keys_for("ana@example.test", "203.0.113.9"), NOW)


def test_ip_lock_holds_for_another_username(conn: sqlite3.Connection) -> None:
    _fail(conn, 5)
    assert is_locked(conn, keys_for("other@example.test", "198.51.100.7"), NOW)


def test_unrelated_user_and_ip_are_not_locked(conn: sqlite3.Connection) -> None:
    _fail(conn, 5)
    assert not is_locked(conn, keys_for("other@example.test", "203.0.113.9"), NOW)


def test_forgive_resets_the_username_only(conn: sqlite3.Connection) -> None:
    _fail(conn, 4)
    forgive(conn, KEYS[0], [])
    conn.commit()
    assert conn.execute("SELECT DISTINCT key FROM login_attempts").fetchall()[0][0] == KEYS[1]
    _fail(conn, 1, keys=[KEYS[1]])
    assert is_locked(conn, KEYS, NOW)  # the IP still has 5


def test_old_rows_are_purged_on_new_failures(conn: sqlite3.Connection) -> None:
    _fail(conn, 3)
    reserve(conn, KEYS, NOW + WINDOW + timedelta(minutes=1))
    assert conn.execute("SELECT count(*) FROM login_attempts").fetchone()[0] == 2


def test_a_refused_attempt_is_not_counted(conn: sqlite3.Connection) -> None:
    _fail(conn, 5)
    assert reserve(conn, KEYS, NOW) is None
    assert conn.execute("SELECT count(*) FROM login_attempts").fetchone()[0] == 10


def test_forgive_drops_this_attempts_own_rows(conn: sqlite3.Connection) -> None:
    _fail(conn, 2)
    ids = reserve(conn, KEYS, NOW)
    assert ids is not None
    forgive(conn, KEYS[0], ids)
    conn.commit()
    keys = [r[0] for r in conn.execute("SELECT key FROM login_attempts")]
    assert keys == [KEYS[1]] * 2  # the IP's two earlier failures stay


def test_parallel_guesses_cannot_all_pass_the_gate(tmp_path: Path) -> None:
    path = tmp_path / "race.db"
    migrate(path)

    def attempt(_: int) -> bool:
        with closing(connect(path)) as c:
            return reserve(c, KEYS, NOW) is not None

    with ThreadPoolExecutor(max_workers=12) as pool:
        allowed = sum(pool.map(attempt, range(24)))
    assert allowed == MAX_FAILURES
