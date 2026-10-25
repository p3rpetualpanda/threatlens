from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app import cli, users
from app.audit import verify
from app.db import connect, migrate
from app.users import MIN_PASSWORD, ROLES, authenticate, create_user

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
PW = "correct horse battery"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    migrate(path)
    return path


@pytest.fixture
def conn(db: Path) -> Iterator[sqlite3.Connection]:
    with closing(connect(db)) as c:
        yield c


def test_create_and_authenticate(conn: sqlite3.Connection) -> None:
    uid = create_user(conn, "Ana@Example.test ", PW, "analyst", NOW)
    user = authenticate(conn, "ana@example.test", PW)
    assert user is not None
    assert (user.id, user.email, user.role) == (uid, "ana@example.test", "analyst")


def test_password_is_stored_as_argon2id_not_plaintext(conn: sqlite3.Connection) -> None:
    create_user(conn, "a@example.test", PW, "viewer", NOW)
    stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert PW not in stored


def test_wrong_password_and_unknown_user_fail_the_same_way(conn: sqlite3.Connection) -> None:
    create_user(conn, "a@example.test", PW, "viewer", NOW)
    assert authenticate(conn, "a@example.test", "wrong password here") is None
    assert authenticate(conn, "nobody@example.test", PW) is None


def test_email_is_case_insensitive_and_unique(conn: sqlite3.Connection) -> None:
    create_user(conn, "a@example.test", PW, "viewer", NOW)
    with pytest.raises(ValueError, match="already exists"):
        create_user(conn, "A@EXAMPLE.TEST", PW, "viewer", NOW)
    assert authenticate(conn, "A@Example.Test", PW) is not None


def test_short_password_is_refused(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="at least"):
        create_user(conn, "a@example.test", "x" * (MIN_PASSWORD - 1), "viewer", NOW)
    assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@", "@b", "a b@example.test"])
def test_bad_email_is_refused(conn: sqlite3.Connection, email: str) -> None:
    with pytest.raises(ValueError, match="email"):
        create_user(conn, email, PW, "viewer", NOW)


def test_unknown_role_is_refused(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="role"):
        create_user(conn, "a@example.test", PW, "root", NOW)


def test_roles_are_ordered_least_to_most_privileged() -> None:
    assert ROLES == ("viewer", "analyst", "lead", "admin")


def test_create_user_is_audited_without_the_password(conn: sqlite3.Connection) -> None:
    uid = create_user(conn, "a@example.test", PW, "lead", NOW, actor="cli")
    row = conn.execute("SELECT actor, action, target, detail FROM audit_log").fetchone()
    assert (row["actor"], row["action"], row["target"]) == ("cli", "user.create", uid)
    assert row["detail"] == '{"email":"a@example.test","role":"lead"}'
    assert PW not in str(tuple(row))
    assert verify(conn) is None


def test_cli_create_admin_reads_password_from_env(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", PW)
    assert cli.main(["create-admin", "root@example.test", "--db", str(db)]) == 0
    out = capsys.readouterr()
    assert PW not in out.out + out.err
    with closing(connect(db)) as c:
        user = authenticate(c, "root@example.test", PW)
    assert user is not None
    assert user.role == "admin"


def test_cli_create_admin_prompts_when_no_env(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATLENS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr("app.cli.getpass.getpass", lambda _prompt="": PW)
    assert cli.main(["create-admin", "root@example.test", "--db", str(db)]) == 0


def test_cli_create_admin_prompt_mismatch_creates_nothing(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("THREATLENS_ADMIN_PASSWORD", raising=False)
    answers = iter([PW, PW + "x"])
    monkeypatch.setattr("app.cli.getpass.getpass", lambda _prompt="": next(answers))
    assert cli.main(["create-admin", "root@example.test", "--db", str(db)]) == 1
    assert "do not match" in capsys.readouterr().err
    with closing(connect(db)) as c:
        assert c.execute("SELECT count(*) FROM users").fetchone()[0] == 0


def test_cli_create_admin_bad_input_exits_1(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", "short")
    assert cli.main(["create-admin", "root@example.test", "--db", str(db)]) == 1
    assert "at least" in capsys.readouterr().err


def test_unknown_email_with_the_dummy_password_still_fails(conn: sqlite3.Connection) -> None:
    assert authenticate(conn, "nobody@example.test", "not-a-real-password") is None


def test_audit_failure_rolls_back_the_user(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("app.users.record", boom)
    with pytest.raises(RuntimeError):
        create_user(conn, "a@example.test", PW, "viewer", NOW)
    assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0


def test_lengths_the_login_form_would_refuse_are_refused_here_too(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="email"):
        create_user(conn, "a" * 250 + "@e.test", PW, "viewer", NOW)
    with pytest.raises(ValueError, match="at most"):
        create_user(conn, "a@example.test", "x" * 1025, "viewer", NOW)


def test_unknown_and_known_emails_both_pay_for_one_argon2_verify(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_user(conn, "a@example.test", PW, "viewer", NOW)
    calls: list[str] = []
    real = users._hasher

    class Spy:
        def verify(self, stored: str, password: str) -> bool:
            calls.append(stored)
            return real.verify(stored, password)

    monkeypatch.setattr(users, "_hasher", Spy())
    authenticate(conn, "a@example.test", "wrong password here")
    authenticate(conn, "nobody@example.test", PW)
    assert len(calls) == 2


def test_an_audit_error_is_not_reported_as_a_duplicate_email(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> None:
        raise sqlite3.IntegrityError("from the audit table")

    monkeypatch.setattr("app.users.record", boom)
    with pytest.raises(sqlite3.IntegrityError):
        create_user(conn, "a@example.test", PW, "viewer", NOW)


def test_cli_create_admin_on_a_locked_database_exits_1(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", PW)

    def locked(*_: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("app.cli.create_user", locked)
    assert cli.main(["create-admin", "root@example.test", "--db", str(db)]) == 1
    assert "locked" in capsys.readouterr().err
