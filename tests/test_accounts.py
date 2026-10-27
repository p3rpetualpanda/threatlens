"""Admin account changes: role, disable, enable. The rules matter more than the happy path."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.accounts import AccountError, change_role, set_disabled
from app.db import connect, migrate
from app.sessions import create_session, get_session
from app.users import User, authenticate, create_user

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
PW = "correct horse battery"


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


def make(conn: sqlite3.Connection, name: str, role: str) -> User:
    uid = create_user(conn, f"{name}@example.test", PW, role, NOW)
    return User(uid, f"{name}@example.test", role)


def actions(conn: sqlite3.Connection) -> list[str]:
    return [r["action"] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]


def test_an_admin_changes_a_role_and_it_is_audited(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    change_role(conn, boss, ann.id, "lead", NOW)
    assert conn.execute("SELECT role FROM users WHERE id = ?", [ann.id]).fetchone()[0] == "lead"
    row = conn.execute("SELECT detail FROM audit_log WHERE action = 'user.role'").fetchone()
    assert "analyst" in row["detail"] and "lead" in row["detail"]


@pytest.mark.parametrize("actor_role", ["viewer", "analyst", "lead"])
def test_only_an_admin_can_change_accounts(conn: sqlite3.Connection, actor_role: str) -> None:
    actor, ann = make(conn, "actor", actor_role), make(conn, "ann", "analyst")
    calls: tuple[Callable[[], None], ...] = (
        lambda: change_role(conn, actor, ann.id, "admin", NOW),
        lambda: set_disabled(conn, actor, ann.id, True, NOW),
    )
    for call in calls:
        with pytest.raises(AccountError) as err:
            call()
        assert err.value.status == 403
    assert conn.execute("SELECT role FROM users WHERE id = ?", [ann.id]).fetchone()[0] == "analyst"


def test_an_admin_cannot_change_or_disable_themselves(conn: sqlite3.Connection) -> None:
    boss, other = make(conn, "boss", "admin"), make(conn, "other", "admin")
    calls: tuple[Callable[[], None], ...] = (
        lambda: change_role(conn, boss, boss.id, "viewer", NOW),
        lambda: set_disabled(conn, boss, boss.id, True, NOW),
    )
    for call in calls:
        with pytest.raises(AccountError) as err:
            call()
        assert err.value.status == 403
    assert other.id  # the second admin exists, so the refusal is the self rule, not last-admin


@pytest.mark.parametrize(
    "stale",
    [
        "UPDATE users SET disabled_at = ? WHERE id = ?",
        "UPDATE users SET role = 'viewer', disabled_at = ? WHERE id = ?",
    ],
)
def test_a_stale_admin_is_refused_so_the_last_admin_always_stays(
    conn: sqlite3.Connection, stale: str
) -> None:
    """The actor's session says admin, but the database (re-read in the write) says otherwise."""
    a, b = make(conn, "a", "admin"), make(conn, "b", "admin")
    conn.execute(stale, [NOW.isoformat(), a.id])
    conn.commit()
    calls: tuple[Callable[[], None], ...] = (
        lambda: change_role(conn, a, b.id, "viewer", NOW),
        lambda: set_disabled(conn, a, b.id, True, NOW),
    )
    for call in calls:
        with pytest.raises(AccountError) as err:
            call()
        assert err.value.status == 403
    assert conn.execute("SELECT role FROM users WHERE id = ?", [b.id]).fetchone()[0] == "admin"


def test_a_demoted_actor_is_refused_even_with_an_admin_session_object(
    conn: sqlite3.Connection,
) -> None:
    a, b, c = make(conn, "a", "admin"), make(conn, "b", "admin"), make(conn, "c", "analyst")
    change_role(conn, b, a.id, "analyst", NOW)
    with pytest.raises(AccountError) as err:
        change_role(conn, a, c.id, "lead", NOW)  # `a` still carries role="admin"
    assert err.value.status == 403


def test_two_admins_may_demote_one_another_in_turn_but_never_both(
    conn: sqlite3.Connection,
) -> None:
    a, b = make(conn, "a", "admin"), make(conn, "b", "admin")
    change_role(conn, a, b.id, "analyst", NOW)  # a stays: fine
    with pytest.raises(AccountError):
        change_role(conn, b, a.id, "analyst", NOW)  # b is no longer an admin
    assert conn.execute("SELECT count(*) FROM users WHERE role = 'admin'").fetchone()[0] == 1


def test_disabling_ends_sessions_and_blocks_login(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    token, _ = create_session(conn, ann.id, NOW)
    assert get_session(conn, token, NOW) is not None
    set_disabled(conn, boss, ann.id, True, NOW)
    assert get_session(conn, token, NOW) is None
    assert authenticate(conn, ann.email, PW) is None
    assert "user.disable" in actions(conn)


def test_a_disabled_users_surviving_session_row_is_not_honoured(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    token, _ = create_session(conn, ann.id, NOW)
    conn.execute("UPDATE users SET disabled_at = ? WHERE id = ?", [NOW.isoformat(), ann.id])
    conn.commit()
    assert boss.id and get_session(conn, token, NOW) is None


def test_enabling_restores_login(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    set_disabled(conn, boss, ann.id, True, NOW)
    set_disabled(conn, boss, ann.id, False, NOW)
    assert authenticate(conn, ann.email, PW) is not None
    assert "user.enable" in actions(conn)


def test_unknown_users_and_roles_are_refused(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    with pytest.raises(AccountError) as err:
        change_role(conn, boss, "no-such-id", "lead", NOW)
    assert err.value.status == 404
    with pytest.raises(AccountError) as err2:
        change_role(conn, boss, ann.id, "superuser", NOW)
    assert err2.value.status == 422
    with pytest.raises(AccountError) as err3:
        set_disabled(conn, boss, "no-such-id", True, NOW)
    assert err3.value.status == 404


def test_the_same_role_is_a_quiet_no_op(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "analyst")
    before = len(actions(conn))
    change_role(conn, boss, ann.id, "analyst", NOW)
    assert len(actions(conn)) == before


def test_a_demotion_applies_to_the_live_session_at_once(conn: sqlite3.Connection) -> None:
    boss, ann = make(conn, "boss", "admin"), make(conn, "ann", "lead")
    token, _ = create_session(conn, ann.id, NOW)
    live = get_session(conn, token, NOW)
    assert live is not None and live.user.role == "lead"
    change_role(conn, boss, ann.id, "viewer", NOW)
    after = get_session(conn, token, NOW)
    assert after is not None and after.user.role == "viewer"  # role is read per request
