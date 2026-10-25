from __future__ import annotations

import copy
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app import ingest
from app.db import connect, migrate
from app.ingest import ingest_findings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 26, 9, 30, tzinfo=UTC)


def _fixture() -> list[dict[str, Any]]:
    return [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # noqa: S608


def test_creates_alerts_and_entities(conn: sqlite3.Connection) -> None:
    items = _fixture()
    result = ingest_findings(conn, items, NOW)
    assert result == {"created": 4, "unchanged": 0, "incidents_touched": []}
    assert _count(conn, "alerts") == 4
    assert _count(conn, "alert_entities") == 9  # 3 + 4 + 2 + 0
    assert _count(conn, "environments") == 2

    row = conn.execute(
        "SELECT * FROM alerts WHERE finding_info_uid = ?", [items[0]["finding_info"]["uid"]]
    ).fetchone()
    assert row["rule"] == "R05"
    assert row["technique"] == "T1059.001"
    assert row["tactic"] == "Execution"
    assert row["environment"] == "lab_a"
    assert row["severity"] == "Medium"
    assert row["beacon_status"] == "new"
    assert row["time"] == "2020-05-02T10:01:00.000+00:00"
    assert row["created_at"] == row["last_ingested_at"] == NOW.isoformat()
    assert row["disposition"] is None
    assert json.loads(row["raw_json"]) == items[0]

    entities = conn.execute(
        "SELECT kind, value FROM alert_entities WHERE alert_id = ? ORDER BY kind", [row["id"]]
    ).fetchall()
    assert [(e["kind"], e["value"]) for e in entities] == [
        ("host", "scranton"),
        ("process", "powershell.exe"),
        ("user", "jhalpert"),
    ]


def test_second_import_is_unchanged(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, _fixture(), NOW)
    before = [tuple(r) for r in conn.execute("SELECT id, raw_json, created_at FROM alerts")]
    result = ingest_findings(conn, _fixture(), LATER)
    assert result == {"created": 0, "unchanged": 4, "incidents_touched": []}
    assert _count(conn, "alerts") == 4
    assert _count(conn, "alert_entities") == 9
    assert before == [tuple(r) for r in conn.execute("SELECT id, raw_json, created_at FROM alerts")]


def test_resend_updates_only_beacon_status(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, _fixture(), NOW)
    changed = copy.deepcopy(_fixture())
    changed[1]["unmapped"]["beacon_status"] = "true_positive"
    changed[1]["severity"] = "Critical"
    changed[1]["finding_info"]["title"] = "rewritten"
    result = ingest_findings(conn, changed, LATER)
    assert result["unchanged"] == 4
    uid = changed[1]["finding_info"]["uid"]
    row = conn.execute("SELECT * FROM alerts WHERE finding_info_uid = ?", [uid]).fetchone()
    assert row["beacon_status"] == "true_positive"
    assert row["severity"] == "High"
    assert json.loads(row["raw_json"]) == _fixture()[1]
    assert row["last_ingested_at"] == LATER.isoformat()
    assert row["created_at"] == NOW.isoformat()


def test_duplicate_uid_in_one_request(conn: sqlite3.Connection) -> None:
    first = _fixture()[0]
    result = ingest_findings(conn, [first, copy.deepcopy(first)], NOW)
    assert result == {"created": 1, "unchanged": 1, "incidents_touched": []}
    assert _count(conn, "alerts") == 1
    assert _count(conn, "alert_entities") == 3


def test_empty_list_touches_nothing(conn: sqlite3.Connection) -> None:
    assert ingest_findings(conn, [], NOW) == {
        "created": 0,
        "unchanged": 0,
        "incidents_touched": [],
    }
    assert _count(conn, "alerts") == 0
    assert _count(conn, "environments") == 0


def test_failure_rolls_back_everything(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ingest._insert_entities
    calls = 0

    def flaky(c: sqlite3.Connection, alert_id: str, entities: dict[str, Any]) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("boom")
        real(c, alert_id, entities)

    monkeypatch.setattr(ingest, "_insert_entities", flaky)
    with pytest.raises(RuntimeError, match="boom"):
        ingest_findings(conn, _fixture(), NOW)
    assert not conn.in_transaction
    assert _count(conn, "alerts") == 0
    assert _count(conn, "alert_entities") == 0
    assert _count(conn, "environments") == 0


def test_failure_after_environment_write_rolls_back(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ingest._touch_environment
    calls = 0

    def flaky(c: sqlite3.Connection, name: str, stamp: str) -> None:
        nonlocal calls
        calls += 1
        real(c, name, stamp)
        if calls == 2:
            raise RuntimeError("boom")

    monkeypatch.setattr(ingest, "_touch_environment", flaky)
    with pytest.raises(RuntimeError, match="boom"):
        ingest_findings(conn, _fixture(), NOW)
    assert _count(conn, "environments") == 0
    assert _count(conn, "alerts") == 0


def test_uid_reused_by_other_environment_credits_owner(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, _fixture()[:1], NOW)  # lab_a owns finding 1
    clash = _fixture()[0]
    clash["unmapped"]["environment"] = "lab_b"
    ingest_findings(conn, [clash], LATER)
    rows = {r["name"]: r["last_import_at"] for r in conn.execute("SELECT * FROM environments")}
    assert rows == {"lab_a": LATER.isoformat()}


def test_duplicate_uid_later_beacon_status_wins(conn: sqlite3.Connection) -> None:
    first, again = _fixture()[0], _fixture()[0]
    again["unmapped"]["beacon_status"] = "true_positive"
    ingest_findings(conn, [first, again], NOW)
    assert conn.execute("SELECT beacon_status FROM alerts").fetchone()[0] == "true_positive"


def test_updates_last_import_at_per_environment(conn: sqlite3.Connection) -> None:
    ingest_findings(conn, _fixture(), NOW)
    only_lab_a = [f for f in _fixture() if f["unmapped"]["environment"] == "lab_a"]
    ingest_findings(conn, only_lab_a, LATER)
    rows = {
        r["name"]: r["last_import_at"]
        for r in conn.execute("SELECT name, last_import_at FROM environments")
    }
    assert rows == {"lab_a": LATER.isoformat(), "lab_b": NOW.isoformat()}


def test_hostile_strings_are_stored_verbatim(conn: sqlite3.Connection) -> None:
    items = _fixture()
    items[0]["finding_info"]["title"] = '<script>alert(1)</script>"><img onerror=x>'
    items[0]["unmapped"]["entities"]["users"] = ["<b>x</b>"]
    ingest_findings(conn, items, NOW)
    raw = conn.execute("SELECT raw_json FROM alerts WHERE rule = 'R05'").fetchone()[0]
    assert "<script>alert(1)</script>" in json.loads(raw)["finding_info"]["title"]
    value = conn.execute("SELECT value FROM alert_entities WHERE value LIKE '<b>%'").fetchone()[0]
    assert value == "<b>x</b>"


def test_open_transaction_is_refused_and_left_alone(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO environments (id, name) VALUES ('e', 'mine')")
    with pytest.raises(sqlite3.OperationalError, match="within a transaction"):
        ingest_findings(conn, _fixture(), NOW)
    assert conn.in_transaction  # the caller's transaction is untouched
    assert _count(conn, "alerts") == 0
