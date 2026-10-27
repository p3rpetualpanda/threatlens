"""Request bodies are capped by bytes read, not by the Content-Length header."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import config
from app.bodylimit import BodyLimit
from app.db import migrate

LOGIN = "/api/v1/login"
COMMENT = "/api/v1/incidents/inc_x/comments"
INGEST = "/api/v1/findings"
JSON = {"content-type": "application/json"}
FORM = {"content-type": "application/x-www-form-urlencoded"}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    return TestClient(main_mod.app, base_url="http://localhost")


def chunked(total: int, size: int = 1024) -> Iterator[bytes]:
    """No Content-Length is sent, so a header check cannot see this body."""
    sent = 0
    while sent < total:
        yield b"x" * min(size, total - sent)
        sent += size


def test_a_chunked_login_body_over_4kb_is_refused(client: TestClient) -> None:
    r = client.post(LOGIN, content=chunked(5000), headers=JSON)
    assert r.status_code == 413


def test_a_chunked_json_body_over_the_default_cap_is_refused(client: TestClient) -> None:
    r = client.post(COMMENT, content=chunked(70_000), headers=JSON)
    assert r.status_code == 413


def test_a_chunked_form_body_over_the_cap_is_refused(client: TestClient) -> None:
    assert client.post("/login", content=chunked(5000), headers=FORM).status_code == 413


def test_a_413_still_carries_the_security_headers(client: TestClient) -> None:
    r = client.post(LOGIN, content=chunked(5000), headers=JSON)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers


def test_an_ordinary_login_still_works(client: TestClient) -> None:
    body = json.dumps({"email": "a@example.test", "password": "pw"})
    assert client.post(LOGIN, content=body, headers=JSON).status_code == 401


def test_ingest_may_exceed_the_default_cap(client: TestClient) -> None:
    r = client.post(INGEST, content=chunked(200_000))  # 401: no key, but not 413
    assert r.status_code == 401


async def _run(path: str, headers: list[tuple[bytes, bytes]], chunks: list[bytes]) -> list[Any]:
    """Drive BodyLimit directly with a scripted body; the inner app reads it all."""
    seen: list[Any] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        while True:
            msg = await receive()
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})

    queue = [{"type": "http.request", "body": c, "more_body": True} for c in chunks]
    queue.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive() -> dict[str, Any]:
        return queue.pop(0)

    async def send(msg: Any) -> None:
        seen.append(msg)

    scope = {"type": "http", "path": path, "headers": headers}
    await BodyLimit(inner, lambda _: {})(scope, receive, send)
    return seen


@pytest.mark.anyio
async def test_the_boundary_is_exact() -> None:
    ok = await _run(LOGIN, [], [b"x" * 4096])
    assert ok[0]["status"] == 200
    over = await _run(LOGIN, [], [b"x" * 4096, b"x"])
    assert over[0]["status"] == 413


@pytest.mark.anyio
async def test_a_lying_content_length_is_caught_by_the_count() -> None:
    lie = [(b"content-length", b"10")]
    out = await _run(LOGIN, lie, [b"x" * 5000])
    assert out[0]["status"] == 413


@pytest.mark.anyio
async def test_a_declared_length_over_the_cap_is_refused_before_reading() -> None:
    big = [(b"content-length", b"99999999")]
    out = await _run(LOGIN, big, [])
    assert out[0]["status"] == 413
