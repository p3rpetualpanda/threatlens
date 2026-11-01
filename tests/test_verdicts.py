"""Verdict export to beacon (spec 6.7 item 7): alerts with a disposition become a verdicts CSV."""

from __future__ import annotations

import csv
import os
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from incident_helpers import add, run

from app import cli, config
from app import verdicts as verdicts_mod
from app.db import connect, migrate
from app.verdicts import build_rows


@pytest.fixture
def conn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[sqlite3.Connection]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as c:
        yield c


def _set(conn: sqlite3.Connection, uid: str, disposition: str | None) -> None:
    conn.execute("UPDATE alerts SET disposition = ? WHERE id = ?", [disposition, uid])
    conn.commit()


def test_empty_database_has_no_rows(conn: sqlite3.Connection) -> None:
    assert build_rows(conn) == []


def test_each_disposition_maps_to_a_beacon_status(conn: sqlite3.Connection) -> None:
    for uid, host in (("a", "h1"), ("b", "h2"), ("c", "h3")):
        add(conn, uid, 1000 * ord(uid), host=host)
    run(conn)
    _set(conn, "a", "true_positive")
    _set(conn, "b", "false_positive")
    _set(conn, "c", "benign_true_positive")
    rows = {r[0]: r for r in build_rows(conn)}
    assert [rows[k][1] for k in "abc"] == ["true_positive", "false_positive", "closed"]
    assert rows["c"][2].startswith("benign:")
    assert rows["a"][2].startswith("threatlens incident ")


def test_alerts_without_a_disposition_are_left_out(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 5000, host="h2")
    run(conn)
    _set(conn, "a", "true_positive")
    assert [r[0] for r in build_rows(conn)] == ["a"]


def test_rows_are_sorted_by_alert_id(conn: sqlite3.Connection) -> None:
    for uid in ("z", "m", "a"):
        add(conn, uid, 100 * ord(uid), host=uid)
    run(conn)
    for uid in ("z", "m", "a"):
        _set(conn, uid, "false_positive")
    assert [r[0] for r in build_rows(conn)] == ["a", "m", "z"]


def test_alert_in_no_incident_still_exports_with_a_plain_reason(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    _set(conn, "a", "true_positive")
    assert build_rows(conn) == [("a", "true_positive", "threatlens")]


def test_reason_holds_no_user_text(conn: sqlite3.Connection) -> None:
    add(conn, "x1", 0, host="h1", rule="=evil")
    run(conn)
    _set(conn, "x1", "false_positive")
    (_, _, reason) = build_rows(conn)[0]
    assert "evil" not in reason and reason.startswith("threatlens incident ")


def _db_with_verdicts(tmp_path: Path) -> Path:
    db = tmp_path / "t.db"
    migrate(db)
    with closing(connect(db)) as c:
        add(c, "a", 0, host="h1")
        add(c, "b", 5000, host="h2")
        c.commit()
        run(c)
        _set(c, "a", "false_positive")
        _set(c, "b", "benign_true_positive")
    return db


def test_cli_writes_the_beacon_header_and_rows(tmp_path: Path) -> None:
    db, out = _db_with_verdicts(tmp_path), tmp_path / "v.csv"
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 0
    with out.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["alert_id", "status", "reason"]
    assert [r[:2] for r in rows[1:]] == [["a", "false_positive"], ["b", "closed"]]


def test_cli_refuses_to_overwrite(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db, out = _db_with_verdicts(tmp_path), tmp_path / "v.csv"
    out.write_text("keep me", encoding="utf-8")
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 1
    assert out.read_text(encoding="utf-8") == "keep me"
    assert "exists" in capsys.readouterr().err


def test_cli_on_a_database_with_no_dispositions_writes_only_the_header(tmp_path: Path) -> None:
    db, out = tmp_path / "e.db", tmp_path / "v.csv"
    migrate(db)
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 0
    assert out.read_text(encoding="utf-8").splitlines() == ["alert_id,status,reason"]


def test_cli_fails_on_a_missing_database_and_creates_nothing(tmp_path: Path) -> None:
    db, out = tmp_path / "typo.db", tmp_path / "v.csv"
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 1
    assert not db.exists() and not out.exists()


def test_failed_write_leaves_no_file_at_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, out = _db_with_verdicts(tmp_path), tmp_path / "v.csv"

    def boom(*_a: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "link", boom)
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 1
    assert not out.exists() and not list(tmp_path.glob("*.tmp"))


def test_formula_looking_alert_ids_are_defused(conn: sqlite3.Connection) -> None:
    add(conn, "=HYPERLINK(1)", 0, host="h1")
    _set(conn, "=HYPERLINK(1)", "false_positive")
    assert build_rows(conn)[0][0] == "'=HYPERLINK(1)"


def test_empty_alert_id_does_not_crash_the_export(conn: sqlite3.Connection) -> None:
    add(conn, "x", 0, host="h1")
    _set(conn, "x", "false_positive")
    conn.execute("UPDATE alerts SET finding_info_uid = '' WHERE id = 'x'")
    assert build_rows(conn)[0][0] == ""


def test_reason_names_the_surviving_incident_after_a_merge(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    ids = run(conn)
    conn.execute(
        "INSERT INTO incidents (id, environment, title, created_at, updated_at) "
        "VALUES ('zzz', 'e', 't', 'x', 'x')"
    )
    conn.execute("UPDATE incidents SET merged_into = 'zzz' WHERE id = ?", [ids[0]])
    conn.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES ('zzz', 'a')")
    _set(conn, "a", "true_positive")
    assert build_rows(conn)[0][2] == "threatlens incident zzz"


def test_a_file_created_during_the_export_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db, out = _db_with_verdicts(tmp_path), tmp_path / "v.csv"
    real = verdicts_mod.build_rows

    def racing(conn: sqlite3.Connection) -> list[tuple[str, str, str]]:
        out.write_text("keep me", encoding="utf-8")  # someone else creates it mid-export
        return real(conn)

    monkeypatch.setattr(cli, "build_rows", racing)
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 1
    assert out.read_text(encoding="utf-8") == "keep me" and not list(tmp_path.glob("*.tmp"))
