from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import app.main as main_mod
from app import config
from app.audit import verify
from app.auth import COOKIE, require_role, router
from app.db import connect, migrate
from app.sessions import Session
from app.users import ROLES, create_user

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
PW = "correct horse battery"
LOGIN = "/api/v1/login"
ME = "/api/v1/me"
LOGOUT = "/api/v1/logout"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    with closing(connect(path)) as conn:
        for role in ROLES:
            create_user(conn, f"{role}@example.test", PW, role, NOW)
    return path


@pytest.fixture
def client(db: Path) -> Iterator[TestClient]:
    with TestClient(main_mod.app, base_url="http://localhost") as c:
        yield c


def _login(client: TestClient, role: str = "analyst", password: str = PW) -> dict[str, object]:
    resp = client.post(LOGIN, json={"email": f"{role}@example.test", "password": password})
    assert resp.status_code == 200, resp.text
    body: dict[str, object] = resp.json()
    return body


def test_login_returns_user_and_csrf_and_a_safe_cookie(client: TestClient) -> None:
    resp = client.post(LOGIN, json={"email": "Analyst@Example.test", "password": PW})
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["email"] == "analyst@example.test"
    assert body["user"]["role"] == "analyst"
    assert len(body["csrf_token"]) >= 43
    assert PW not in resp.text
    cookie = resp.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE}=")
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert "secure" not in cookie  # plain http on localhost


def test_cookie_is_secure_off_localhost(db: Path) -> None:
    with TestClient(main_mod.app, base_url="https://threatlens.example") as c:
        resp = c.post(LOGIN, json={"email": "analyst@example.test", "password": PW})
        assert "secure" in resp.headers["set-cookie"].lower()
        assert resp.headers["strict-transport-security"].startswith("max-age=")


def test_wrong_password_and_unknown_user_look_identical(client: TestClient) -> None:
    bad = client.post(LOGIN, json={"email": "analyst@example.test", "password": "wrong password"})
    unknown = client.post(LOGIN, json={"email": "nobody@example.test", "password": PW})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()
    assert "set-cookie" not in bad.headers


@pytest.mark.parametrize(
    "body",
    [{}, {"email": "a@example.test"}, {"email": "a@example.test", "password": "x" * 1025}],
)
def test_login_rejects_malformed_bodies(client: TestClient, body: dict[str, str]) -> None:
    assert client.post(LOGIN, json=body).status_code == 422


def test_five_failures_lock_even_the_right_password(client: TestClient, db: Path) -> None:
    for _ in range(5):
        r = client.post(LOGIN, json={"email": "analyst@example.test", "password": "wrong one!"})
        assert r.status_code == 401
    locked = client.post(LOGIN, json={"email": "analyst@example.test", "password": PW})
    assert locked.status_code == 429
    assert locked.headers["retry-after"] == "900"
    with closing(connect(db)) as conn:
        actions = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
    assert actions.count("login.locked") == 1


def test_lock_covers_unknown_usernames_too(client: TestClient) -> None:
    for _ in range(5):
        client.post(LOGIN, json={"email": "ghost@example.test", "password": "wrong one!"})
    r = client.post(LOGIN, json={"email": "ghost@example.test", "password": PW})
    assert r.status_code == 429


def test_good_login_resets_the_username_counter_but_not_the_ip(
    client: TestClient, db: Path
) -> None:
    for _ in range(4):
        client.post(LOGIN, json={"email": "lead@example.test", "password": "wrong one!"})
    _login(client, "lead")
    with closing(connect(db)) as conn:
        keys = [r[0] for r in conn.execute("SELECT key FROM login_attempts")]
    assert [k.split(":")[0] for k in keys] == ["ip"] * 4  # the user key is gone, the IP's stays


def test_login_is_audited_and_the_chain_holds(client: TestClient, db: Path) -> None:
    _login(client)
    with closing(connect(db)) as conn:
        row = conn.execute(
            "SELECT actor, action FROM audit_log WHERE action = 'login.success'"
        ).fetchone()
        assert row["actor"] == "analyst@example.test"
        assert verify(conn) is None


def test_me_needs_a_valid_session(client: TestClient) -> None:
    assert client.get(ME).status_code == 401
    client.cookies.set(COOKIE, "garbage")
    assert client.get(ME).status_code == 401
    client.cookies.clear()
    _login(client, "viewer")
    resp = client.get(ME)
    assert resp.status_code == 200
    assert resp.json()["user"]["role"] == "viewer"


def test_login_replaces_a_planted_session_cookie(client: TestClient) -> None:
    client.cookies.set(COOKIE, "planted-by-attacker", domain="localhost", path="/")
    resp = client.post(LOGIN, json={"email": "analyst@example.test", "password": PW})
    assert resp.status_code == 200
    assert "planted-by-attacker" not in resp.headers["set-cookie"]  # a fresh token is issued
    other = TestClient(main_mod.app, base_url="http://localhost")
    other.cookies.set(COOKIE, "planted-by-attacker")
    assert other.get(ME).status_code == 401  # the planted value never became a session


def test_logout_needs_csrf_then_invalidates(client: TestClient) -> None:
    csrf = str(_login(client)["csrf_token"])
    assert client.post(LOGOUT).status_code == 403
    assert client.post(LOGOUT, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.get(ME).status_code == 200  # still logged in after the rejected attempts
    cookie = client.cookies.get(COOKIE)
    assert client.post(LOGOUT, headers={"X-CSRF-Token": csrf}).status_code == 204
    other = TestClient(main_mod.app, base_url="http://localhost")
    assert cookie is not None
    other.cookies.set(COOKIE, cookie)
    assert other.get(ME).status_code == 401  # the old token is dead server-side


def test_logout_without_a_session_is_401(client: TestClient) -> None:
    assert client.post(LOGOUT, headers={"X-CSRF-Token": "x"}).status_code == 401


def test_another_sessions_csrf_token_is_rejected(client: TestClient) -> None:
    other = TestClient(main_mod.app, base_url="http://localhost")
    other_csrf = str(_login(other, "lead")["csrf_token"])
    _login(client)
    assert client.post(LOGOUT, headers={"X-CSRF-Token": other_csrf}).status_code == 403


def test_security_headers_everywhere_but_docs(client: TestClient) -> None:
    for path in ("/health", ME):
        h = client.get(path).headers
        assert "default-src 'self'" in h["content-security-policy"]
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        assert h["cache-control"] == "no-store"
        assert "strict-transport-security" not in h  # plain http
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers  # Swagger UI loads from a CDN
    assert docs.headers["x-content-type-options"] == "nosniff"


def test_locked_database_is_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3

    def locked(*_: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("app.auth.authenticate", locked)
    r = client.post(LOGIN, json={"email": "analyst@example.test", "password": PW})
    assert r.status_code == 503
    assert r.headers["retry-after"] == "5"


# --- require_role, on a throwaway app so the real routes stay untouched ---


@pytest.fixture
def gated(db: Path) -> Iterator[TestClient]:
    mini = FastAPI()
    mini.include_router(router)

    @mini.get("/read")
    def read(_: Session = Depends(require_role("viewer"))) -> dict[str, str]:  # noqa: B008
        return {"ok": "read"}

    @mini.post("/work")
    def work(_: Session = Depends(require_role("analyst"))) -> dict[str, str]:  # noqa: B008
        return {"ok": "work"}

    @mini.post("/admin")
    def admin(_: Session = Depends(require_role("admin"))) -> dict[str, str]:  # noqa: B008
        return {"ok": "admin"}

    with TestClient(mini, base_url="http://localhost") as c:
        yield c


@pytest.mark.parametrize(
    ("role", "path", "status"),
    [
        ("viewer", "/read", 200),
        ("viewer", "/work", 403),
        ("analyst", "/work", 200),
        ("analyst", "/admin", 403),
        ("lead", "/work", 200),
        ("lead", "/admin", 403),
        ("admin", "/admin", 200),
        ("admin", "/work", 200),
    ],
)
def test_roles_include_the_ones_below(gated: TestClient, role: str, path: str, status: int) -> None:
    csrf = str(_login(gated, role)["csrf_token"])
    resp = gated.get(path) if path == "/read" else gated.post(path, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == status


def test_anonymous_is_401_and_missing_csrf_is_403(gated: TestClient) -> None:
    assert gated.get("/read").status_code == 401
    assert gated.post("/work").status_code == 401
    _login(gated, "admin")
    assert gated.post("/work").status_code == 403  # logged in, no CSRF header
    assert gated.get("/read").status_code == 200  # safe methods need no CSRF header


def test_an_unknown_role_name_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="role"):
        require_role("root")
