"""Hardening batch: 500 headers, ingest key throttle, session write throttle, operator CLI."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.api as api_mod
import app.main as main_mod
from app import config
from app.apikeys import create_api_key
from app.cli import main as cli
from app.db import connect, migrate
from app.sessions import IDLE_TIMEOUT, create_session, get_session
from app.users import authenticate, create_user

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
PW = "correct horse battery"
URL = "/api/v1/findings"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    return path


@pytest.fixture
def client(db: Path) -> Iterator[TestClient]:
    with TestClient(main_mod.app, raise_server_exceptions=False) as c:
        yield c


def test_an_unhandled_error_is_a_500_with_the_security_headers(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> str:
        raise RuntimeError("secret internals")

    monkeypatch.setattr(api_mod, "_check", boom)
    r = client.post(URL, json=[], headers={"Authorization": "Bearer x"})
    assert r.status_code == 500
    assert "secret internals" not in r.text
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers


def test_repeated_bad_ingest_keys_are_throttled_even_for_a_good_key(
    client: TestClient, db: Path
) -> None:
    with closing(connect(db)) as conn:
        good = create_api_key(conn, "lab", datetime.now(UTC))
    for _ in range(5):
        assert (
            client.post(URL, json=[], headers={"Authorization": "Bearer nope"}).status_code == 401
        )
    r = client.post(URL, json=[], headers={"Authorization": f"Bearer {good}"})
    assert r.status_code == 429
    assert "retry-after" in r.headers


def test_good_ingest_keys_are_never_counted(client: TestClient, db: Path) -> None:
    with closing(connect(db)) as conn:
        good = create_api_key(conn, "lab", datetime.now(UTC))
    for _ in range(8):
        assert (
            client.post(URL, json=[], headers={"Authorization": f"Bearer {good}"}).status_code
            != 429
        )


def _expires(db: Path) -> str:
    with closing(connect(db)) as conn:
        return str(conn.execute("SELECT expires_at FROM sessions").fetchone()[0])


def test_a_session_is_not_rewritten_on_every_request(db: Path) -> None:
    with closing(connect(db)) as conn:
        uid = create_user(conn, "a@example.test", PW, "analyst", NOW)
        token, _ = create_session(conn, uid, NOW)
        first = _expires(db)
        assert get_session(conn, token, NOW + timedelta(seconds=30)) is not None
        assert _expires(db) == first  # too soon to bother writing
        assert get_session(conn, token, NOW + timedelta(minutes=10)) is not None
    assert _expires(db) == (NOW + timedelta(minutes=10) + IDLE_TIMEOUT).isoformat()


def test_operator_cli_disables_enables_and_revokes(db: Path) -> None:
    with closing(connect(db)) as conn:
        uid = create_user(conn, "ann@example.test", PW, "analyst", NOW)
        token, _ = create_session(conn, uid, datetime.now(UTC))
    args = ["--db", str(db)]
    assert cli(["user", "revoke-sessions", "Ann@Example.test", *args]) == 0
    with closing(connect(db)) as conn:
        assert get_session(conn, token, datetime.now(UTC)) is None
        assert authenticate(conn, "ann@example.test", PW) is not None  # still allowed to log in
    assert cli(["user", "disable", "ann@example.test", *args]) == 0
    with closing(connect(db)) as conn:
        assert authenticate(conn, "ann@example.test", PW) is None
    assert cli(["user", "enable", "ann@example.test", *args]) == 0
    with closing(connect(db)) as conn:
        assert authenticate(conn, "ann@example.test", PW) is not None
        actions = [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE actor = 'cli'")]
    assert actions == ["user.sessions_revoked", "user.disable", "user.enable"]


def test_operator_cli_refuses_an_unknown_user(db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(["user", "disable", "nobody@example.test", "--db", str(db)]) == 1
    assert "no such user" in capsys.readouterr().err
