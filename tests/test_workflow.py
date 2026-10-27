from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from incident_helpers import NOW, add, run

from app import workflow
from app.audit import verify
from app.db import connect, migrate
from app.users import User, create_user
from app.workflow import WorkflowError

PW = "correct horse battery"


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def user(conn: sqlite3.Connection, role: str, name: str | None = None) -> User:
    email = f"{name or role}@example.test"
    return User(create_user(conn, email, PW, role, NOW), email, role)


def one_incident(conn: sqlite3.Connection) -> str:
    add(conn, "a", 0, host="h")
    add(conn, "b", 5, host="h", rule="R02")
    return run(conn)[0]


def fail(status: int, fn: Callable[..., Any], *args: Any) -> None:
    with pytest.raises(WorkflowError) as exc:
        fn(*args)
    assert exc.value.status == status


def row(conn: sqlite3.Connection, iid: str) -> sqlite3.Row:
    r: sqlite3.Row = conn.execute("SELECT * FROM incidents WHERE id = ?", [iid]).fetchone()
    return r


def test_take_sets_owner_status_touched_and_audits(conn: sqlite3.Connection) -> None:
    iid, ann = one_incident(conn), user(conn, "analyst")
    out = workflow.take(conn, ann, iid, NOW)
    assert (out["owner"], out["status"]) == (ann.id, "in_progress")
    assert row(conn, iid)["touched"] == 1
    assert conn.execute("SELECT 1 FROM audit_log WHERE action = 'incident.take'").fetchone()
    fail(409, workflow.take, conn, user(conn, "analyst", "bob"), iid, NOW)  # already owned
    fail(404, workflow.take, conn, ann, "nope", NOW)


def test_assign_needs_lead_and_an_analyst_target(conn: sqlite3.Connection) -> None:
    iid, lead, ann = one_incident(conn), user(conn, "lead"), user(conn, "analyst")
    viewer = user(conn, "viewer")
    fail(403, workflow.assign, conn, ann, iid, ann.email, NOW)
    fail(422, workflow.assign, conn, lead, iid, viewer.email, NOW)
    fail(422, workflow.assign, conn, lead, iid, "ghost@example.test", NOW)
    assert workflow.assign(conn, lead, iid, ann.email.upper(), NOW)["owner"] == ann.id
    out = workflow.assign(conn, lead, iid, None, NOW)
    assert (out["owner"], out["status"]) == (None, "new")


def test_resolve_needs_disposition_and_stamps_alerts(conn: sqlite3.Connection) -> None:
    iid, ann = one_incident(conn), user(conn, "analyst")
    workflow.take(conn, ann, iid, NOW)
    fail(409, workflow.set_status, conn, ann, iid, "resolved", NOW)
    conn.execute("UPDATE alerts SET disposition = 'false_positive' WHERE id = 'a'")
    workflow.set_disposition(conn, ann, iid, "true_positive", NOW)
    out = workflow.set_status(conn, ann, iid, "resolved", NOW + timedelta(hours=1))
    assert out["resolved_at"] is not None
    got = {r["id"]: r["disposition"] for r in conn.execute("SELECT id, disposition FROM alerts")}
    assert got == {"a": "false_positive", "b": "true_positive"}  # an earlier call stays
    fail(409, workflow.set_disposition, conn, ann, iid, "false_positive", NOW)
    fail(403, workflow.set_status, conn, ann, iid, "in_progress", NOW)  # reopen is for leads
    lead = user(conn, "lead")
    reopened = workflow.set_status(conn, lead, iid, "in_progress", NOW)
    assert (reopened["status"], reopened["resolved_at"]) == ("in_progress", None)


def test_analyst_only_works_own_incidents_and_bad_values(conn: sqlite3.Connection) -> None:
    iid, ann, bob = one_incident(conn), user(conn, "analyst"), user(conn, "analyst", "bob")
    workflow.take(conn, ann, iid, NOW)
    fail(403, workflow.set_status, conn, bob, iid, "new", NOW)
    fail(403, workflow.set_disposition, conn, bob, iid, "false_positive", NOW)
    fail(422, workflow.set_status, conn, ann, iid, "closed", NOW)
    fail(409, workflow.set_status, conn, ann, iid, "in_progress", NOW)  # no change
    fail(422, workflow.set_disposition, conn, ann, iid, "maybe", NOW)
    assert workflow.set_disposition(conn, ann, iid, None, NOW)["disposition"] is None
    lead = user(conn, "lead")
    assert workflow.assign(conn, lead, iid, None, NOW)["status"] == "new"


def test_in_progress_needs_an_owner(conn: sqlite3.Connection) -> None:
    iid, lead = one_incident(conn), user(conn, "lead")
    workflow.set_disposition(conn, lead, iid, "false_positive", NOW)
    fail(409, workflow.set_status, conn, lead, iid, "in_progress", NOW)


def test_comment_stores_trimmed_text_and_limits_it(conn: sqlite3.Connection) -> None:
    iid, ann = one_incident(conn), user(conn, "analyst")
    workflow.add_comment(conn, ann, iid, "  <b>hi</b>  ", NOW)
    got = conn.execute("SELECT author, body FROM comments").fetchone()
    assert (got["author"], got["body"]) == (ann.email, "<b>hi</b>")  # raw; escaped on output
    fail(422, workflow.add_comment, conn, ann, iid, "   ", NOW)
    fail(422, workflow.add_comment, conn, ann, iid, "x" * 5001, NOW)
    assert row(conn, iid)["touched"] == 0  # a comment alone does not freeze the grouping


def test_merge_keeps_target_and_refreshes_it(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 600, host="h2")
    run(conn)
    ids = [r["id"] for r in conn.execute("SELECT id FROM incidents ORDER BY first_seen")]
    lead, ann = user(conn, "lead"), user(conn, "analyst")
    fail(403, workflow.merge, conn, ann, ids[1], ids[0], NOW)
    fail(422, workflow.merge, conn, lead, ids[0], ids[0], NOW)
    out = workflow.merge(conn, lead, ids[1], ids[0], NOW)
    assert out["id"] == ids[0]
    assert row(conn, ids[1])["merged_into"] == ids[0]
    kept = row(conn, ids[0])
    assert kept["title"].endswith("(+1 more)") and kept["touched"] == 1
    assert kept["last_seen"] > kept["first_seen"]
    fail(409, workflow.merge, conn, lead, ids[1], ids[0], NOW)  # already merged
    run(conn)  # a later correlation run must not undo it
    assert row(conn, ids[1])["merged_into"] == ids[0]
    n = conn.execute("SELECT count(*) FROM incident_alerts WHERE incident_id = ?", [ids[0]])
    assert n.fetchone()[0] == 2


def test_merge_refuses_other_environment_and_resolved(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h", env="e1")
    add(conn, "b", 0, host="h", env="e2")
    run(conn, "e1")
    run(conn, "e2")
    x, y = (r["id"] for r in conn.execute("SELECT id FROM incidents ORDER BY environment"))
    lead = user(conn, "lead")
    fail(422, workflow.merge, conn, lead, x, y, NOW)
    add(conn, "c", 600, host="k", env="e1")
    run(conn, "e1")
    z = conn.execute(
        "SELECT id FROM incidents WHERE environment = 'e1' AND id != ?", [x]
    ).fetchone()
    conn.execute("UPDATE incidents SET status = 'resolved' WHERE id = ?", [z["id"]])
    fail(409, workflow.merge, conn, lead, z["id"], x, NOW)


def test_split_moves_pins_and_survives_recorrelation(conn: sqlite3.Connection) -> None:
    iid = one_incident(conn)
    lead = user(conn, "lead")
    fail(403, workflow.split, conn, user(conn, "analyst"), iid, ["b"], NOW)
    fail(422, workflow.split, conn, lead, iid, [], NOW)
    fail(422, workflow.split, conn, lead, iid, ["zzz"], NOW)
    fail(422, workflow.split, conn, lead, iid, ["a", "b"], NOW)  # nothing left behind
    new_id = workflow.split(conn, lead, iid, ["b"], NOW)["id"]
    assert new_id != iid
    assert row(conn, new_id)["title"] == "Title R02"
    assert row(conn, iid)["title"] == "Title R01"
    run(conn)
    owner = {r["alert_id"]: r["incident_id"] for r in conn.execute("SELECT * FROM incident_alerts")}
    assert owner == {"a": iid, "b": new_id}
    assert conn.execute("SELECT pinned FROM incident_alerts WHERE alert_id = 'b'").fetchone()[0]


def test_every_action_is_audited_and_chain_verifies(conn: sqlite3.Connection) -> None:
    iid, lead = one_incident(conn), user(conn, "lead")
    workflow.take(conn, lead, iid, NOW)
    workflow.add_comment(conn, lead, iid, "ok", NOW)
    workflow.split(conn, lead, iid, ["b"], NOW)
    actions = {r["action"] for r in conn.execute("SELECT action FROM audit_log")}
    assert {"incident.take", "incident.comment", "incident.split"} <= actions
    conn.commit()
    assert verify(conn) is None


def test_reopen_and_change_disposition_follows_to_alerts(conn: sqlite3.Connection) -> None:
    iid, ann, lead = one_incident(conn), user(conn, "analyst"), user(conn, "lead")
    workflow.take(conn, ann, iid, NOW)
    workflow.set_disposition(conn, ann, iid, "false_positive", NOW)
    workflow.set_status(conn, ann, iid, "resolved", NOW)
    workflow.set_status(conn, lead, iid, "in_progress", NOW)
    workflow.set_disposition(conn, ann, iid, "true_positive", NOW)
    workflow.set_status(conn, ann, iid, "resolved", NOW)
    got = {r["disposition"] for r in conn.execute("SELECT disposition FROM alerts")}
    assert got == {"true_positive"}


def test_owned_incident_cannot_return_to_new(conn: sqlite3.Connection) -> None:
    iid, ann = one_incident(conn), user(conn, "analyst")
    workflow.take(conn, ann, iid, NOW)
    fail(409, workflow.set_status, conn, ann, iid, "new", NOW)


def test_merge_of_an_emptied_incident_does_not_crash(conn: sqlite3.Connection) -> None:
    iid = one_incident(conn)
    lead = user(conn, "lead")
    conn.execute("UPDATE incidents SET touched = 0")
    other = "other"
    conn.execute(
        "INSERT INTO incidents (id, environment, title, created_at, updated_at) "
        "VALUES (?, 'e', '', ?, ?)",
        [other, NOW.isoformat(), NOW.isoformat()],
    )
    workflow.merge(conn, lead, other, iid, NOW)
    assert row(conn, other)["merged_into"] == iid


def test_playbook_step_toggles_audits_and_freezes_grouping(conn: sqlite3.Connection) -> None:
    iid, ann = one_incident(conn), user(conn, "analyst")
    conn.execute("UPDATE alerts SET technique = 'T1110'")
    workflow.take(conn, ann, iid, NOW)
    steps = workflow.incident_steps(conn, iid)
    assert steps and not any(done for _, done in steps)
    sid = steps[0][0].id
    assert sid.startswith("brute-force.")  # the technique picked its own playbook
    workflow.set_step(conn, ann, iid, sid, True, NOW)
    assert [done for s, done in workflow.incident_steps(conn, iid) if s.id == sid] == [True]
    workflow.set_step(conn, ann, iid, sid, False, NOW)
    assert not any(done for _, done in workflow.incident_steps(conn, iid))
    actions = [r["action"] for r in conn.execute("SELECT action FROM audit_log")]
    assert actions.count("incident.step") == 2
    assert verify(conn) is None


def test_playbook_step_refuses_unknown_step_stranger_and_resolved(
    conn: sqlite3.Connection,
) -> None:
    iid, ann, bob = one_incident(conn), user(conn, "analyst"), user(conn, "analyst", "bob")
    workflow.take(conn, ann, iid, NOW)
    sid = workflow.incident_steps(conn, iid)[0][0].id
    fail(422, workflow.set_step, conn, ann, iid, "nope.1", True, NOW)
    fail(403, workflow.set_step, conn, bob, iid, sid, True, NOW)
    workflow.set_disposition(conn, ann, iid, "true_positive", NOW)
    workflow.set_status(conn, ann, iid, "resolved", NOW)
    fail(409, workflow.set_step, conn, ann, iid, sid, True, NOW)
