from __future__ import annotations

from contextlib import closing
from pathlib import Path

import pytest

from app import config, flash
from app.db import connect, migrate


@pytest.fixture(autouse=True)
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "flash.db"
    migrate(path)
    monkeypatch.setattr(config, "DB_PATH", path)
    return path


def test_a_message_is_read_once_and_only_by_its_own_session() -> None:
    flash.put("s1", "done", "take")
    assert flash.pop("s2", "done") is None
    assert flash.pop("s1", "done") == "take"
    assert flash.pop("s1", "done") is None


def test_a_message_survives_a_new_connection_and_holds_structured_values() -> None:
    flash.put("s1", "key", ["lab", "tok"])  # a second worker or a restart opens a new connection
    assert flash.pop("s1", "key") == ["lab", "tok"]


def test_the_session_key_is_stored_hashed() -> None:
    flash.put("secret-csrf", "done", "take")
    with closing(connect(config.DB_PATH)) as conn:
        assert "secret-csrf" not in str(conn.execute("SELECT * FROM flash").fetchall()[0][:])


def test_an_expired_message_is_dropped_and_old_rows_are_purged() -> None:
    flash.put("s1", "done", "take")
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("UPDATE flash SET at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
    assert flash.pop("s1", "done") is None
    flash.put("s2", "done", "take")
    flash.put("s3", "done", "take")
    with closing(connect(config.DB_PATH)) as conn:
        assert conn.execute("SELECT count(*) FROM flash").fetchone()[0] == 2
