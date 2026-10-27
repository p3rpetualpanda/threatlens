from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from incident_helpers import NOW, add, run

from app.db import connect, migrate
from app.users import create_user


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
    assert row["risk_score"] == 20
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


def test_touched_incident_keeps_its_title(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    (iid,) = run(conn)
    conn.execute("UPDATE incidents SET touched = 1, title = 'Analyst title' WHERE id = ?", [iid])
    add(conn, "b", 10, host="h")
    run(conn)
    assert conn.execute("SELECT title FROM incidents WHERE id=?", [iid]).fetchone()[0] == (
        "Analyst title"
    )


def test_merge_gives_winner_the_losers_owner_and_status(conn: sqlite3.Connection) -> None:
    older, newer = _bridge_setup(conn)
    uid = create_user(conn, "o@example.test", "correct horse battery", "analyst", NOW)
    owner = uid if isinstance(uid, str) else uid.id
    conn.execute("UPDATE incidents SET created_at = '2026-01-01' WHERE id = ?", [older])
    conn.execute(
        "UPDATE incidents SET touched = 1, status = 'in_progress', owner = ? WHERE id = ?",
        [owner, newer],
    )
    conn.execute("UPDATE incidents SET touched = 1 WHERE id = ?", [older])  # both touched
    add(conn, "c", 100, host="h1", user="u")
    add(conn, "d", 200, host="h2", user="u")
    run(conn)
    row = conn.execute("SELECT * FROM incidents WHERE merged_into IS NULL").fetchone()
    assert (row["id"], row["owner"], row["status"], row["touched"]) == (
        older,
        owner,
        "in_progress",
        1,
    )


def test_auto_stoplisted_values_are_recorded(conn: sqlite3.Connection) -> None:
    for i in range(50):
        add(conn, f"a{i:02}", 0, host="h")
    run(conn)
    rows = conn.execute("SELECT too_common FROM incidents").fetchall()
    assert len(rows) == 50
    assert {r["too_common"] for r in rows} == {'["host:h"]'}


def _two_bridgeable(conn: sqlite3.Connection) -> tuple[str, str]:
    older, newer = _bridge_setup(conn)
    conn.execute("UPDATE incidents SET created_at = '2026-01-01' WHERE id = ?", [older])
    return older, newer


def _bridge(conn: sqlite3.Connection) -> None:
    add(conn, "c", 100, host="h1", user="u")
    add(conn, "d", 200, host="h2", user="u")
    run(conn)


def test_out_of_range_timestamp_does_not_abort(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    conn.execute(
        "UPDATE alerts SET raw_json = ? WHERE id = 'a'",
        [json.dumps({"finding_info": {"first_seen_time": 10**18, "last_seen_time": 10**18}})],
    )
    (iid,) = run(conn)
    assert members(conn, iid) == {"a"}


def test_merge_keeps_winner_owner_and_disposition_and_records_the_dropped(
    conn: sqlite3.Connection,
) -> None:
    older, newer = _two_bridgeable(conn)
    alice = create_user(conn, "a@example.test", "correct horse battery", "analyst", NOW)
    bob = create_user(conn, "b@example.test", "correct horse battery", "analyst", NOW)
    a_id, b_id = (u if isinstance(u, str) else u.id for u in (alice, bob))
    conn.execute(
        "UPDATE incidents SET owner = ?, disposition = 'true_positive' WHERE id = ?", [a_id, older]
    )
    conn.execute(
        "UPDATE incidents SET owner = ?, disposition = 'false_positive', touched = 1 WHERE id = ?",
        [b_id, newer],
    )
    _bridge(conn)
    win = conn.execute("SELECT * FROM incidents WHERE merged_into IS NULL").fetchone()
    assert (win["id"], win["owner"], win["disposition"]) == (newer, b_id, "false_positive")
    detail = conn.execute("SELECT detail FROM audit_log WHERE action='incident.merge'").fetchone()
    assert json.loads(detail[0]) == {
        "merged": older,
        "dropped": {"owner": a_id, "disposition": "true_positive"},
    }


def test_merge_audit_detail_without_losses(conn: sqlite3.Connection) -> None:
    older, newer = _two_bridgeable(conn)
    _bridge(conn)
    detail = conn.execute("SELECT detail FROM audit_log WHERE action='incident.merge'").fetchone()
    assert json.loads(detail[0]) == {"merged": newer}
    assert members(conn, older) == {"a", "b", "c", "d"}


def test_merge_ors_touched_from_loser(conn: sqlite3.Connection) -> None:
    older, newer = _two_bridgeable(conn)
    conn.execute("UPDATE incidents SET touched = 1 WHERE id = ?", [newer])
    conn.execute("UPDATE incidents SET touched = 0 WHERE id = ?", [older])
    _bridge(conn)
    # newer is touched so it wins; its flag stays set
    assert conn.execute("SELECT touched FROM incidents WHERE id=?", [newer]).fetchone()[0] == 1


def test_merge_keeps_done_playbook_step_and_leaves_loser_none(conn: sqlite3.Connection) -> None:
    older, newer = _two_bridgeable(conn)
    for iid, done in ((older, 0), (newer, 1)):
        conn.execute(
            "INSERT INTO playbook_progress (incident_id, step, done, updated_at) "
            "VALUES (?, 's1', ?, ?)",
            [iid, done, NOW.isoformat()],
        )
    _bridge(conn)  # older wins (oldest created_at); its step was open, the loser's was done
    rows = conn.execute("SELECT incident_id, done FROM playbook_progress").fetchall()
    assert [tuple(r) for r in rows] == [(older, 1)]


def test_merge_carries_related_incident_to_winner(conn: sqlite3.Connection) -> None:
    older, newer = _two_bridgeable(conn)
    conn.execute(
        "INSERT INTO incidents (id, environment, title, status, created_at, updated_at) "
        "VALUES ('res', 'e', 't', 'resolved', '2025-01-01', '2025-01-01')"
    )
    conn.execute("UPDATE incidents SET related_incident = 'res' WHERE id = ?", [newer])
    _bridge(conn)
    row = conn.execute("SELECT related_incident FROM incidents WHERE id = ?", [older]).fetchone()
    assert row[0] == "res"


def test_merged_incident_is_not_resurrected(conn: sqlite3.Connection) -> None:
    _two_bridgeable(conn)
    _bridge(conn)
    assert run(conn) == []
    assert (
        conn.execute("SELECT COUNT(*) FROM incidents WHERE merged_into IS NULL").fetchone()[0] == 1
    )


def test_missing_times_and_title_fall_back(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h", rule="R09")
    conn.execute("UPDATE alerts SET raw_json = '{}' WHERE id = 'a'")
    (iid,) = run(conn)
    row = conn.execute("SELECT title, first_seen, last_seen FROM incidents WHERE id=?", [iid])
    row = row.fetchone()
    assert tuple(row) == ("R09", "2026-01-01T09:00:00.000+00:00", "2026-01-01T09:00:00.000+00:00")


def test_risk_score_follows_membership(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    conn.execute("UPDATE alerts SET tactic = 'Execution' WHERE id = 'a'")
    (iid,) = run(conn)
    assert conn.execute("SELECT risk_score FROM incidents WHERE id=?", [iid]).fetchone()[0] == 20
    add(conn, "b", 10, host="h")
    conn.execute("UPDATE alerts SET tactic = 'Credential Access', severity = 'High' WHERE id='b'")
    assert run(conn) == [iid]
    row = conn.execute("SELECT risk_score, risk_factors FROM incidents WHERE id=?", [iid])
    row = row.fetchone()
    factors = json.loads(row["risk_factors"])
    assert row["risk_score"] == 35 + 8 + 10
    assert sum(f["points"] for f in factors) == row["risk_score"]
