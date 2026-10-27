from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from incident_helpers import NOW, add, run

from app.db import connect, migrate


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def members(conn: sqlite3.Connection, iid: str) -> set[str]:
    rows = conn.execute("SELECT alert_id FROM incident_alerts WHERE incident_id = ?", [iid])
    return {r["alert_id"] for r in rows}


def incident_of(conn: sqlite3.Connection, alert: str) -> str:
    return str(
        conn.execute(
            "SELECT incident_id FROM incident_alerts WHERE alert_id = ?", [alert]
        ).fetchone()["incident_id"]
    )


def test_untouched_component_keeps_existing_id(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    add(conn, "b", 10, host="h")
    (iid,) = run(conn)
    stamp = conn.execute("SELECT updated_at FROM incidents WHERE id=?", [iid]).fetchone()[0]
    assert run(conn, now=NOW + timedelta(days=1)) == []
    assert conn.execute("SELECT updated_at FROM incidents WHERE id=?", [iid]).fetchone()[0] == stamp
    assert members(conn, iid) == {"a", "b"}


def test_new_alert_joins_existing_incident(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    (iid,) = run(conn)
    add(conn, "b", 30, host="h")
    assert run(conn) == [iid]
    assert members(conn, iid) == {"a", "b"}


def test_two_incidents_merge_when_bridged(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 300, host="h2")
    run(conn)
    old, newer = incident_of(conn, "a"), incident_of(conn, "b")
    conn.execute("UPDATE incidents SET created_at = '2026-01-01' WHERE id = ?", [old])
    add(conn, "c", 100, host="h1", user="u")
    add(conn, "d", 200, host="h2", user="u")
    run(conn)
    assert incident_of(conn, "b") == old
    assert (
        conn.execute("SELECT merged_into FROM incidents WHERE id=?", [newer]).fetchone()[0] == old
    )
    assert members(conn, old) == {"a", "b", "c", "d"}


def _bridge_setup(conn: sqlite3.Connection) -> tuple[str, str]:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 300, host="h2")
    run(conn)
    return incident_of(conn, "a"), incident_of(conn, "b")


def test_touched_incident_survives_merge_with_owner_and_comments(
    conn: sqlite3.Connection,
) -> None:
    older, newer = _bridge_setup(conn)
    conn.execute("UPDATE incidents SET created_at = '2026-01-01' WHERE id = ?", [older])
    conn.execute("UPDATE incidents SET touched = 1, status = 'in_progress' WHERE id = ?", [newer])
    conn.execute(
        "INSERT INTO comments (id, incident_id, author, body, created_at) "
        "VALUES ('c1', ?, 'x', 'hi', ?)",
        [older, NOW.isoformat()],
    )
    conn.execute(
        "INSERT INTO playbook_progress (incident_id, step, done, updated_at) "
        "VALUES (?, 's1', 1, ?)",
        [older, NOW.isoformat()],
    )
    add(conn, "c", 100, host="h1", user="u")
    add(conn, "d", 200, host="h2", user="u")
    run(conn)
    row = conn.execute("SELECT status, merged_into FROM incidents WHERE id=?", [newer]).fetchone()
    assert (row["status"], row["merged_into"]) == ("in_progress", None)
    assert (
        conn.execute("SELECT merged_into FROM incidents WHERE id=?", [older]).fetchone()[0] == newer
    )
    assert conn.execute("SELECT incident_id FROM comments").fetchone()[0] == newer
    assert conn.execute("SELECT incident_id FROM playbook_progress").fetchone()[0] == newer


def test_audit_row_on_merge(conn: sqlite3.Connection) -> None:
    _bridge_setup(conn)
    add(conn, "c", 100, host="h1", user="u")
    add(conn, "d", 200, host="h2", user="u")
    run(conn)
    row = conn.execute(
        "SELECT actor, action FROM audit_log WHERE action='incident.merge'"
    ).fetchone()
    assert tuple(row) == ("system", "incident.merge")


def test_touched_incident_never_splits(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    add(conn, "b", 10, host="h")
    (iid,) = run(conn)
    conn.execute("UPDATE incidents SET touched = 1 WHERE id = ?", [iid])
    conn.execute("UPDATE alert_entities SET value = 'other' WHERE alert_id = 'b'")  # link gone
    run(conn)
    assert members(conn, iid) == {"a", "b"}


def test_untouched_incident_splits_when_link_disappears(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    add(conn, "b", 10, host="h")
    (iid,) = run(conn)
    conn.execute("UPDATE alert_entities SET value = 'other' WHERE alert_id = 'b'")
    run(conn)
    assert incident_of(conn, "a") == iid
    assert incident_of(conn, "b") != iid


def test_resolved_incident_is_frozen_and_new_alert_gets_related_incident(
    conn: sqlite3.Connection,
) -> None:
    add(conn, "a", 0, host="h")
    (iid,) = run(conn)
    conn.execute("UPDATE incidents SET status = 'resolved' WHERE id = ?", [iid])
    add(conn, "b", 30, host="h")
    (new,) = run(conn)
    assert new != iid
    assert members(conn, iid) == {"a"}
    assert members(conn, new) == {"b"}
    assert (
        conn.execute("SELECT related_incident FROM incidents WHERE id=?", [new]).fetchone()[0]
        == iid
    )


def test_pinned_alert_stays(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 10, host="h2")
    run(conn)
    ia = incident_of(conn, "a")
    conn.execute(
        "UPDATE incident_alerts SET incident_id = ?, pinned = 1 WHERE alert_id = 'b'", [ia]
    )
    run(conn)
    assert incident_of(conn, "b") == ia


def test_incident_title_risk_and_times(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h", rule="R05")
    add(conn, "b", 30, host="h", rule="R07")
    (iid,) = run(conn)
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", [iid]).fetchone()
    assert row["title"] == "Title R05 (+1 more)"
    assert row["risk_score"] is None
    assert row["first_seen"] == "2026-01-01T09:00:00.000+00:00"
    assert row["last_seen"] == "2026-01-01T09:30:00.000+00:00"


def test_alert_with_no_linking_entities_gets_its_own_incident(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0)
    (iid,) = run(conn)
    assert members(conn, iid) == {"a"}


def test_environments_do_not_mix(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h", env="e1")
    add(conn, "b", 1, host="h", env="e2")
    run(conn, "e1")
    run(conn, "e2")
    assert incident_of(conn, "a") != incident_of(conn, "b")
