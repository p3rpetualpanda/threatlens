from __future__ import annotations

import copy
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from app import cli
from app.apikeys import check_api_key
from app.db import connect
from app.ingest import IngestResult, ingest_findings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"


def _lines() -> list[str]:
    return FIXTURE.read_text("utf-8").splitlines()


def _alerts(db: Path) -> int:
    with closing(sqlite3.connect(db)) as conn:
        return int(conn.execute("SELECT count(*) FROM alerts").fetchone()[0])


def test_import_fixture(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "t.db"
    assert cli.main(["import", str(FIXTURE), "--db", str(db)]) == 0
    assert "created 4" in capsys.readouterr().out
    assert _alerts(db) == 4


def test_import_twice_is_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "t.db"
    cli.main(["import", str(FIXTURE), "--db", str(db)])
    capsys.readouterr()
    assert cli.main(["import", str(FIXTURE), "--db", str(db)]) == 0
    assert "unchanged 4" in capsys.readouterr().out
    assert _alerts(db) == 4


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    src = tmp_path / "f.jsonl"
    src.write_text("\n" + "\n\n".join(_lines()) + "\n\n", encoding="utf-8")
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 0
    assert _alerts(db) == 4


def test_bad_json_line_names_the_line_and_imports_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = _lines()
    lines[2] = "{not json"
    src = tmp_path / "f.jsonl"
    src.write_text("\n".join(lines), encoding="utf-8")
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 1
    assert "line 3" in capsys.readouterr().err
    assert not db.exists()  # bad input never touches the database


def test_schema_invalid_finding_imports_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    items = [json.loads(line) for line in _lines()]
    del items[1]["finding_info"]["uid"]
    src = tmp_path / "f.jsonl"
    src.write_text("\n".join(json.dumps(i) for i in items), encoding="utf-8")
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 1
    assert "line 2" in capsys.readouterr().err
    assert not db.exists()


def test_missing_file_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["import", str(tmp_path / "nope.jsonl"), "--db", str(tmp_path / "t.db")]) == 1
    assert "nope.jsonl" in capsys.readouterr().err


def test_non_utf8_file_exits_1(tmp_path: Path) -> None:
    src = tmp_path / "f.jsonl"
    src.write_bytes(b"\xff\xfe\n")
    assert cli.main(["import", str(src), "--db", str(tmp_path / "t.db")]) == 1


def test_create_api_key_prints_only_the_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "t.db"
    assert cli.main(["create-api-key", "demo", "--db", str(db)]) == 0
    token = capsys.readouterr().out.strip()
    assert " " not in token
    with closing(connect(db)) as conn:
        assert check_api_key(conn, token, "ingest") is True


def test_db_defaults_to_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "env.db"
    monkeypatch.setenv("THREATLENS_DB_PATH", str(db))
    assert cli.main(["import", str(FIXTURE)]) == 0
    assert _alerts(db) == 4


def test_large_file_is_ingested_in_batches_of_1000(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base: list[dict[str, Any]] = [json.loads(line) for line in _lines()]
    items = []
    for n in range(2_500):
        item = copy.deepcopy(base[n % 4])
        item["finding_info"]["uid"] = f"00000000-0000-4000-8000-{n:012d}"
        items.append(json.dumps(item))
    src = tmp_path / "big.jsonl"
    src.write_text("\n".join(items), encoding="utf-8")

    sizes: list[int] = []
    real = ingest_findings

    def spy(
        conn: sqlite3.Connection, findings: list[dict[str, Any]], now: datetime, actor: str
    ) -> IngestResult:
        sizes.append(len(findings))
        return real(conn, findings, now, actor)

    monkeypatch.setattr("app.cli.ingest_findings", spy)
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 0
    assert sizes == [1000, 1000, 500]
    assert _alerts(db) == 2_500


def test_no_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_many_errors_are_capped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "f.jsonl"
    src.write_text("\n".join("{}" for _ in range(20)), encoding="utf-8")
    assert cli.main(["import", str(src), "--db", str(tmp_path / "t.db")]) == 1
    err = capsys.readouterr().err
    assert err.count("line ") == cli.MAX_SHOWN
    assert "more errors" in err


def test_error_line_number_counts_blank_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    items = [json.loads(line) for line in _lines()]
    del items[1]["finding_info"]["uid"]
    src = tmp_path / "f.jsonl"
    src.write_text(
        "\n\n" + json.dumps(items[0]) + "\n\n\n" + json.dumps(items[1]), encoding="utf-8"
    )
    assert cli.main(["import", str(src), "--db", str(tmp_path / "t.db")]) == 1
    assert "line 6" in capsys.readouterr().err


def test_deeply_nested_line_exits_1_not_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "f.jsonl"
    src.write_text("[" * 1_000_000, encoding="utf-8")
    assert cli.main(["import", str(src), "--db", str(tmp_path / "t.db")]) == 1
    assert "line 1" in capsys.readouterr().err


def test_bom_and_unicode_line_separators_are_handled(tmp_path: Path) -> None:
    items = [json.loads(line) for line in _lines()]
    items[0]["finding_info"]["title"] = "a\u2028b\u0085c"  # legal inside a JSON string
    body = "\n".join(json.dumps(i, ensure_ascii=False) for i in items)
    src = tmp_path / "f.jsonl"
    src.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))  # BOM, as PowerShell writes it
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 0
    assert _alerts(db) == 4


def test_database_error_midway_reports_batches_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    base = [json.loads(line) for line in _lines()]
    rows = []
    for n in range(1_500):
        item = copy.deepcopy(base[0])
        item["finding_info"]["uid"] = f"00000000-0000-4000-8000-{n:012d}"
        rows.append(json.dumps(item))
    src = tmp_path / "big.jsonl"
    src.write_text("\n".join(rows), encoding="utf-8")
    real = ingest_findings
    calls = 0

    def flaky(
        conn: sqlite3.Connection, findings: list[dict[str, Any]], now: datetime, actor: str
    ) -> IngestResult:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.OperationalError("database is locked")
        return real(conn, findings, now, actor)

    monkeypatch.setattr("app.cli.ingest_findings", flaky)
    db = tmp_path / "t.db"
    assert cli.main(["import", str(src), "--db", str(db)]) == 1
    err = capsys.readouterr().err
    assert "database is locked" in err
    assert "1000 findings were already stored" in err
    assert _alerts(db) == 1_000
