"""/account: users change their own password; wrong guesses are throttled."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient
from incident_helpers import NOW

import app.main as main_mod
from app import config
from app.db import connect, migrate
from app.users import authenticate, create_user

PW = "correct horse battery"
NEW = "a brand new passphrase"
FORM = {"content-type": "application/x-www-form-urlencoded"}


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    with closing(connect(path)) as conn:
        create_user(conn, "ann@example.test", PW, "viewer", NOW)
    yield path


def login() -> tuple[TestClient, str]:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    body = urlencode({"email": "ann@example.test", "password": PW})
    assert c.post("/login", content=body, headers=FORM).status_code == 303
    return c, c.get("/api/v1/me").json()["csrf_token"]


def change(c: TestClient, csrf: str, current: str, new: str, again: str) -> httpx.Response:
    body = urlencode({"csrf": csrf, "current": current, "new": new, "again": again})
    r: httpx.Response = c.post("/account/password", content=body, headers=FORM)
    return r


def ok(db: Path, password: str) -> bool:
    with closing(connect(db)) as conn:
        return authenticate(conn, "ann@example.test", password) is not None


def test_the_page_needs_a_login(db: Path) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    assert c.get("/account").status_code == 303


def test_a_change_works_ends_other_sessions_and_keeps_this_one(db: Path) -> None:
    (c, csrf), (other, _) = login(), login()
    r = change(c, csrf, PW, NEW, NEW)
    assert (r.status_code, r.headers["location"]) == (303, "/account")
    assert ok(db, NEW) and not ok(db, PW)
    assert c.get("/account").status_code == 200  # this session survives
    assert other.get("/account").status_code == 303  # the other one was signed out
    with closing(connect(db)) as conn:
        row = conn.execute("SELECT detail FROM audit_log WHERE action = 'user.password_changed'")
        assert NEW not in row.fetchone()[0]


@pytest.mark.parametrize(
    ("current", "new", "again", "status", "text"),
    [
        (PW, NEW, "something else entirely", 422, "differ"),
        (PW, "short", "short", 422, "at least"),
        ("wrong password here", NEW, NEW, 403, "current password is wrong"),
    ],
)
def test_bad_changes_are_refused_and_change_nothing(
    db: Path, current: str, new: str, again: str, status: int, text: str
) -> None:
    c, csrf = login()
    r = change(c, csrf, current, new, again)
    assert r.status_code == status and text in r.text
    assert ok(db, PW)


def test_missing_csrf_is_refused(db: Path) -> None:
    c, _ = login()
    assert change(c, "wrong", PW, NEW, NEW).status_code == 403
    assert ok(db, PW)


def test_guessing_the_current_password_is_throttled(db: Path) -> None:
    c, csrf = login()
    for _ in range(5):
        assert change(c, csrf, "wrong password here", NEW, NEW).status_code == 403
    r = change(c, csrf, PW, NEW, NEW)  # even the right one is refused while locked
    assert r.status_code == 429 and ok(db, PW)
