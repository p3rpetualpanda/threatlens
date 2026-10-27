"""Behind a TLS proxy: uvicorn's ProxyHeadersMiddleware (what `--proxy-headers` installs)
rewrites the client address and scheme, but only for a trusted peer. These tests wrap the app
the same way."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import app.main as main_mod
from app import config
from app.db import connect, migrate
from app.users import create_user

PW = "correct horse battery"
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
LOGIN = "/api/v1/login"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    with closing(connect(path)) as conn:
        create_user(conn, "ann@example.test", PW, "analyst", NOW)
    yield path


def client(trusted: str) -> TestClient:
    """The test client's peer address is the literal host name "testclient"."""
    wrapped = ProxyHeadersMiddleware(main_mod.app, trusted_hosts=trusted)  # type: ignore[arg-type]
    return TestClient(wrapped, base_url="http://localhost")  # type: ignore[arg-type]


def attempt(c: TestClient, email: str, ip: str, password: str = "bad") -> httpx.Response:  # noqa: S107
    r: httpx.Response = c.post(
        LOGIN,
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"},
    )
    return r


def test_a_trusted_proxy_makes_the_session_cookie_secure_and_adds_hsts(db: Path) -> None:
    # the proxy talks to the app on a local name, so the Host header alone would say "plain http"
    r = attempt(client("testclient"), "ann@example.test", "198.51.100.1", PW)
    assert r.status_code == 200
    assert "secure" in r.headers["set-cookie"].lower()
    assert "strict-transport-security" in r.headers


def test_an_untrusted_peer_cannot_claim_https_or_an_address(db: Path) -> None:
    c = client("10.9.9.9")
    r = attempt(c, "ann@example.test", "198.51.100.1", PW)
    assert "strict-transport-security" not in r.headers
    assert "secure" not in r.headers["set-cookie"].lower()
    for i in range(5):  # a different forged address each time still lands in one bucket
        attempt(c, f"nobody{i}@example.test", f"198.51.100.{10 + i}")
    assert attempt(c, "other@example.test", "198.51.100.99").status_code == 429


def test_forwarded_addresses_get_their_own_lockout_bucket(db: Path) -> None:
    c = client("testclient")
    for i in range(5):
        attempt(c, f"nobody{i}@example.test", "198.51.100.1")
    assert attempt(c, "other@example.test", "198.51.100.1").status_code == 429
    assert attempt(c, "other@example.test", "198.51.100.2").status_code == 401


def test_a_forged_first_hop_does_not_change_the_recorded_address(db: Path) -> None:
    # the proxy appends the real peer, so the client's own entry sits to the left
    attempt(client("testclient"), "ann@example.test", "203.0.113.50, 198.51.100.1", PW)
    with closing(connect(db)) as conn:
        row = conn.execute("SELECT detail FROM audit_log WHERE action = 'login.success'").fetchone()
    assert json.loads(row["detail"])["ip"] == "198.51.100.1"
