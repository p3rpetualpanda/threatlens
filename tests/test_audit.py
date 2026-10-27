from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app import cli
from app.apikeys import create_api_key, lookup_api_key, revoke_api_key
from app.audit import append_only, record, verify
from app.db import connect, migrate
from app.ingest import ingest_findings

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    migrate(path)
    return path


@pytest.fixture
def conn(db: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(db)) as c:
        yield c


def _fill(conn: sqlite3.Connection, n: int = 3) -> None:
    for i in range(n):
        record(conn, "alice", "thing.done", f"t{i}", {"i": i}, NOW)
    conn.commit()


def test_empty_log_verifies(conn: sqlite3.Connection) -> None:
    assert verify(conn) is None


def test_rows_are_chained_and_verify(conn: sqlite3.Connection) -> None:
    _fill(conn)
    rows = conn.execute("SELECT id, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
    assert [r["id"] for r in rows] == [1, 2, 3]
    assert rows[0]["prev_hash"] == "0" * 64
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert len({r["hash"] for r in rows}) == 3
    assert verify(conn) is None


def _unlock(conn: sqlite3.Connection) -> None:
    """Drop the append-only triggers, as someone with the database file could."""
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")


def test_the_log_cannot_be_edited_or_deleted_through_sql(conn: sqlite3.Connection) -> None:
    _fill(conn)
    assert append_only(conn)
    for sql in ("UPDATE audit_log SET actor = 'x'", "DELETE FROM audit_log"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(sql)
    _unlock(conn)
    assert not append_only(conn)


@pytest.mark.parametrize("column", ["at", "actor", "action", "target", "detail", "prev_hash"])
def test_editing_any_field_is_detected(conn: sqlite3.Connection, column: str) -> None:
    _fill(conn)
    _unlock(conn)
    conn.execute(f"UPDATE audit_log SET {column} = 'tampered' WHERE id = 2")  # noqa: S608
    conn.commit()
    assert verify(conn) == 2


def test_renumbering_a_row_is_detected(conn: sqlite3.Connection) -> None:
    _fill(conn)
    _unlock(conn)
    conn.execute("UPDATE audit_log SET id = 99 WHERE id = 3")
    conn.commit()
    assert verify(conn) == 99


def test_deleting_a_middle_row_is_detected(conn: sqlite3.Connection) -> None:
    _fill(conn)
    _unlock(conn)
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    conn.commit()
    assert verify(conn) == 3


def test_rewriting_a_hash_breaks_the_next_row(conn: sqlite3.Connection) -> None:
    _fill(conn)
    _unlock(conn)
    conn.execute("UPDATE audit_log SET hash = 'f' WHERE id = 1")
    conn.commit()
    assert verify(conn) == 1


def test_missing_hash_is_detected(conn: sqlite3.Connection) -> None:
    _fill(conn)
    _unlock(conn)
    conn.execute("UPDATE audit_log SET hash = NULL WHERE id = 3")
    conn.commit()
    assert verify(conn) == 3


def test_record_does_not_commit(conn: sqlite3.Connection, db: Path) -> None:
    record(conn, "alice", "thing.done", None, None, NOW)
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


def test_detail_is_canonical_json(conn: sqlite3.Connection) -> None:
    record(conn, "a", "x", None, {"b": 1, "a": "é"}, NOW)
    conn.commit()
    assert conn.execute("SELECT detail FROM audit_log").fetchone()[0] == '{"a":"é","b":1}'


def test_api_key_create_and_revoke_are_audited(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab", NOW)
    key_id = lookup_api_key(conn, token, "ingest")
    assert key_id is not None
    revoke_api_key(conn, key_id, NOW)
    rows = conn.execute("SELECT action, target, detail FROM audit_log ORDER BY id").fetchall()
    assert [r["action"] for r in rows] == ["api_key.create", "api_key.revoke"]
    assert all(r["target"] == key_id for r in rows)
    assert token not in "".join(str(tuple(r)) for r in rows)  # the secret is never logged
    assert verify(conn) is None


def test_a_repeat_revoke_writes_no_second_audit_row(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab", NOW)
    key_id = lookup_api_key(conn, token, "ingest")
    assert key_id is not None
    revoke_api_key(conn, key_id, NOW)
    revoke_api_key(conn, key_id, NOW)
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["api_key.create", "api_key.revoke"]


def test_parallel_writers_keep_one_unbroken_chain(db: Path) -> None:
    def work(worker: int) -> None:
        with closing(connect(db)) as c:
            for i in range(10):
                record(c, f"w{worker}", "thing.done", str(i), None, NOW)
                c.commit()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(work, range(4)))
    with closing(connect(db)) as c:
        ids = [r[0] for r in c.execute("SELECT id FROM audit_log ORDER BY id")]
        assert ids == list(range(1, 41))
        assert verify(c) is None


def test_lookup_api_key_wrong_scope_or_revoked(conn: sqlite3.Connection) -> None:
    token = create_api_key(conn, "lab", NOW)
    key_id = lookup_api_key(conn, token, "ingest")
    assert key_id is not None
    assert lookup_api_key(conn, token, "admin") is None
    revoke_api_key(conn, key_id, NOW)
    assert lookup_api_key(conn, token, "ingest") is None


def _findings() -> list[dict[str, object]]:
    import json

    return [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]


def test_ingest_writes_one_audit_row(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, _findings(), NOW, actor="api_key:k1")
    row = conn.execute("SELECT actor, action, detail FROM audit_log").fetchone()
    assert (row["actor"], row["action"]) == ("api_key:k1", "findings.ingest")
    assert row["detail"] == '{"created":4,"unchanged":0}'
    assert verify(conn) is None


def test_empty_ingest_writes_no_audit_row(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, [], NOW)
    assert conn.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


def test_failed_ingest_leaves_no_audit_row(conn: sqlite3.Connection) -> None:
    bad = _findings()
    del bad[2]["finding_info"]
    with pytest.raises(Exception):  # noqa: B017
        ingest_findings(conn, bad, NOW)
    assert conn.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


def test_cli_verify_ok_and_tampered(
    db: Path, capsys: pytest.CaptureFixture[str], conn: sqlite3.Connection
) -> None:
    _fill(conn)
    assert cli.main(["audit", "verify", "--db", str(db)]) == 0
    assert "3 rows" in capsys.readouterr().out
    _unlock(conn)
    conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 2")
    conn.commit()
    assert cli.main(["audit", "verify", "--db", str(db)]) == 1
    assert "row 2" in capsys.readouterr().err


def test_cli_import_and_create_key_are_audited(db: Path, conn: sqlite3.Connection) -> None:
    assert cli.main(["import", str(FIXTURE), "--db", str(db)]) == 0
    assert cli.main(["create-api-key", "lab", "--db", str(db)]) == 0
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
    assert actions == ["findings.ingest", "api_key.create"]
    assert {r[0] for r in conn.execute("SELECT actor FROM audit_log")} == {"cli"}


def test_cli_verify_on_a_missing_database_exits_1_and_creates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "typo.db"
    assert cli.main(["audit", "verify", "--db", str(missing)]) == 1
    assert "no database" in capsys.readouterr().err
    assert not missing.exists()
