from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app import cli
from app.anchor import (
    AnchorError,
    append_anchor,
    check_anchor,
    generate_key,
    load_key,
)
from app.audit import record
from app.db import connect, migrate

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
DAY = timedelta(hours=24)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    migrate(path)
    return path


@pytest.fixture
def conn(db: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(db)) as c:
        for i in range(3):
            record(c, "tester", "test.event", f"t{i}", None, NOW)
        c.commit()
        yield c


@pytest.fixture
def key(tmp_path: Path) -> bytes:
    generate_key(tmp_path / "audit.key")
    return load_key(tmp_path / "audit.key")


@pytest.fixture
def anchor(tmp_path: Path) -> Path:
    return tmp_path / "anchors.jsonl"


def _unlock_and_rewrite(conn: sqlite3.Connection) -> None:
    """Someone with the file: drop the triggers and replace the whole log with a clean chain."""
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit_log")
    for i in range(3):
        record(conn, "tester", "test.event", f"forged{i}", None, NOW)
    conn.commit()


def test_a_fresh_anchor_checks_out(conn: sqlite3.Connection, key: bytes, anchor: Path) -> None:
    line = append_anchor(conn, key, anchor, NOW)
    assert line["id"] == 3
    assert check_anchor(conn, key, anchor, NOW, DAY) is None


def test_anchors_accumulate_and_all_are_checked(
    conn: sqlite3.Connection, key: bytes, anchor: Path
) -> None:
    append_anchor(conn, key, anchor, NOW)
    record(conn, "tester", "test.event", "t3", None, NOW)
    conn.commit()
    append_anchor(conn, key, anchor, NOW + timedelta(hours=1))
    assert len(anchor.read_text().splitlines()) == 2
    assert check_anchor(conn, key, anchor, NOW + timedelta(hours=1), DAY) is None


def test_a_rewritten_log_with_recomputed_hashes_is_caught(
    conn: sqlite3.Connection, key: bytes, anchor: Path
) -> None:
    append_anchor(conn, key, anchor, NOW)
    _unlock_and_rewrite(conn)
    msg = check_anchor(conn, key, anchor, NOW, DAY)
    assert msg is not None and "changed" in msg


def test_rows_cut_off_the_tail_are_caught(
    conn: sqlite3.Connection, key: bytes, anchor: Path
) -> None:
    append_anchor(conn, key, anchor, NOW)
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id = 3")
    conn.commit()
    msg = check_anchor(conn, key, anchor, NOW, DAY)
    assert msg is not None and "missing" in msg


def test_a_forged_anchor_line_is_caught(conn: sqlite3.Connection, key: bytes, anchor: Path) -> None:
    append_anchor(conn, key, anchor, NOW)
    entry = json.loads(anchor.read_text())
    entry["hash"] = "0" * 64  # the attacker edits the anchor to match a rewritten log
    anchor.write_text(json.dumps(entry) + "\n")
    msg = check_anchor(conn, key, anchor, NOW, DAY)
    assert msg is not None and "line 1" in msg


def test_the_wrong_key_fails(
    conn: sqlite3.Connection, key: bytes, anchor: Path, tmp_path: Path
) -> None:
    append_anchor(conn, key, anchor, NOW)
    generate_key(tmp_path / "other.key")
    msg = check_anchor(conn, load_key(tmp_path / "other.key"), anchor, NOW, DAY)
    assert msg is not None and "line 1" in msg


def test_a_stale_newest_anchor_fails(conn: sqlite3.Connection, key: bytes, anchor: Path) -> None:
    append_anchor(conn, key, anchor, NOW)
    msg = check_anchor(conn, key, anchor, NOW + DAY + timedelta(minutes=1), DAY)
    assert msg is not None and "older" in msg


def test_deleting_the_newest_anchor_line_shows_as_stale(
    conn: sqlite3.Connection, key: bytes, anchor: Path
) -> None:
    append_anchor(conn, key, anchor, NOW)
    append_anchor(conn, key, anchor, NOW + timedelta(hours=30))
    anchor.write_text(anchor.read_text().splitlines()[0] + "\n")
    msg = check_anchor(conn, key, anchor, NOW + timedelta(hours=30), DAY)
    assert msg is not None and "older" in msg


@pytest.mark.parametrize("content", ["", "not json\n", '{"id": 1}\n', "[]\n"])
def test_a_missing_empty_or_malformed_anchor_file_fails(
    conn: sqlite3.Connection, key: bytes, anchor: Path, content: str
) -> None:
    assert check_anchor(conn, key, anchor, NOW, DAY) is not None  # file does not exist
    anchor.write_text(content)
    assert check_anchor(conn, key, anchor, NOW, DAY) is not None


def test_anchoring_an_empty_log_is_refused(db: Path, key: bytes, anchor: Path) -> None:
    with closing(connect(db)) as c, pytest.raises(AnchorError, match="empty"):
        append_anchor(c, key, anchor, NOW)


def test_the_key_file_is_created_once_and_must_be_valid(tmp_path: Path) -> None:
    path = tmp_path / "k"
    generate_key(path)
    assert len(path.read_text().strip()) == 64
    with pytest.raises(AnchorError, match="exists"):
        generate_key(path)
    with pytest.raises(AnchorError, match="cannot read"):
        load_key(tmp_path / "nope")
    short = tmp_path / "short"
    short.write_text("abcd")
    with pytest.raises(AnchorError, match="64 hex"):
        load_key(short)


def test_cli_keygen_anchor_and_verify(
    db: Path, conn: sqlite3.Connection, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    kf, af = tmp_path / "k", tmp_path / "a.jsonl"
    base = ["audit", "--db", str(db), "--key-file", str(kf), "--anchor-file", str(af)]
    assert cli.main(["audit", "keygen", str(kf)]) == 0
    assert cli.main([*base[:1], "anchor", *base[1:]]) == 0
    assert cli.main([*base[:1], "verify", *base[1:]]) == 0
    assert "anchored" in capsys.readouterr().out
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id = 3")
    conn.commit()
    assert cli.main([*base[:1], "verify", *base[1:]]) == 1
    assert "missing" in capsys.readouterr().err


def test_cli_verify_without_an_anchor_setting_still_works(
    db: Path, conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["audit", "verify", "--db", str(db)]) == 0
    assert "no anchor configured" in capsys.readouterr().out


def test_cli_anchor_needs_both_settings(
    db: Path, conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["audit", "anchor", "--db", str(db)]) == 1
    assert "key file" in capsys.readouterr().err
