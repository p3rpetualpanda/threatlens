from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.apikeys import create_api_key, lookup_api_key, revoke_api_key
from app.db import connect, migrate

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 26, 9, 30, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def test_token_is_long_urlsafe_and_unique(conn: sqlite3.Connection) -> None:
    a = create_api_key(conn, "lab_a", NOW)
    b = create_api_key(conn, "lab_a", NOW)
    assert len(a) >= 43
    assert re.fullmatch(r"[A-Za-z0-9_-]+", a)
    assert a != b


def test_only_a_hash_is_stored(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab_a", NOW)
    row = conn.execute("SELECT * FROM api_keys").fetchone()
    assert token not in tuple(row)
    assert re.fullmatch(r"[0-9a-f]{64}", row["token_hash"])
    assert (row["name"], row["scope"], row["created_at"]) == ("lab_a", "ingest", NOW.isoformat())
    assert row["revoked_at"] is None


def test_fresh_key_is_accepted_for_ingest(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab_a", NOW)
    assert lookup_api_key(conn, token, "ingest") is not None


def test_other_scope_is_refused(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab_a", NOW)
    assert lookup_api_key(conn, token, "admin") is None


def test_unknown_and_empty_tokens_are_refused(conn: sqlite3.Connection) -> None:
    create_api_key(conn, "lab_a", NOW)
    assert lookup_api_key(conn, "not-a-real-token", "ingest") is None
    assert lookup_api_key(conn, "", "ingest") is None


def test_revoked_key_is_refused_and_others_keep_working(conn: sqlite3.Connection) -> None:
    gone = create_api_key(conn, "old", NOW)
    kept = create_api_key(conn, "new", NOW)
    key_id = conn.execute("SELECT id FROM api_keys WHERE name = 'old'").fetchone()["id"]
    revoke_api_key(conn, key_id, LATER)
    assert lookup_api_key(conn, gone, "ingest") is None
    assert lookup_api_key(conn, kept, "ingest") is not None
    row = conn.execute("SELECT revoked_at FROM api_keys WHERE id = ?", [key_id]).fetchone()
    assert row["revoked_at"] == LATER.isoformat()


def test_revoke_unknown_key_fails_loudly(conn: sqlite3.Connection) -> None:
    with pytest.raises(KeyError):
        revoke_api_key(conn, "nope", NOW)


def test_revoke_twice_keeps_first_time(conn: sqlite3.Connection) -> None:
    create_api_key(conn, "k", NOW)
    key_id = conn.execute("SELECT id FROM api_keys").fetchone()["id"]
    revoke_api_key(conn, key_id, NOW)
    revoke_api_key(conn, key_id, LATER)
    assert conn.execute("SELECT revoked_at FROM api_keys").fetchone()[0] == NOW.isoformat()


def test_create_is_visible_to_a_second_connection(tmp_path: Path) -> None:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as writer:
        token = create_api_key(writer, "k", NOW)
    with closing(connect(path)) as reader:
        assert lookup_api_key(reader, token, "ingest") is not None
