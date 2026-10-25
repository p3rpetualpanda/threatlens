from __future__ import annotations

import copy
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import config
from app.apikeys import create_api_key, revoke_api_key
from app.db import connect

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"
URL = "/api/v1/findings"
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


def _fixture() -> list[dict[str, Any]]:
    return [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Path, str]]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    with TestClient(main_mod.app) as client:
        with closing(connect(db)) as conn:
            token = create_api_key(conn, "lab", NOW)
        yield client, db, token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _alerts(db: Path) -> int:
    with closing(sqlite3.connect(db)) as conn:
        return int(conn.execute("SELECT count(*) FROM alerts").fetchone()[0])


def test_happy_path_creates_alerts(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    resp = client.post(URL, json=_fixture(), headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json() == {"created": 4, "unchanged": 0, "incidents_touched": []}
    assert _alerts(db) == 4


def test_same_request_twice_is_unchanged(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    client.post(URL, json=_fixture(), headers=_auth(token))
    resp = client.post(URL, json=_fixture(), headers=_auth(token))
    assert resp.json() == {"created": 0, "unchanged": 4, "incidents_touched": []}
    assert _alerts(db) == 4


def test_missing_header_is_401(api: tuple[TestClient, Path, str]) -> None:
    client, db, _ = api
    resp = client.post(URL, json=_fixture())
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert _alerts(db) == 0


def test_wrong_scheme_is_401(api: tuple[TestClient, Path, str]) -> None:
    client, _, token = api
    resp = client.post(URL, json=_fixture(), headers={"Authorization": f"Basic {token}"})
    assert resp.status_code == 401


def test_unknown_and_revoked_keys_get_the_same_401(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    with closing(connect(db)) as conn:
        key_id = conn.execute("SELECT id FROM api_keys").fetchone()["id"]
        revoke_api_key(conn, key_id, NOW)
    revoked = client.post(URL, json=_fixture(), headers=_auth(token))
    unknown = client.post(URL, json=_fixture(), headers=_auth("nope"))
    missing = client.post(URL, json=_fixture())
    assert revoked.status_code == unknown.status_code == missing.status_code == 401
    assert revoked.json() == unknown.json() == missing.json()


def test_auth_is_checked_before_the_body_is_read(api: tuple[TestClient, Path, str]) -> None:
    client, _, _ = api
    big = b"x" * (10 * 1024 * 1024 + 1)
    assert client.post(URL, content=big).status_code == 401


def test_body_over_10_mb_is_413(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    big = b"x" * (10 * 1024 * 1024 + 1)
    resp = client.post(URL, content=big, headers=_auth(token))
    assert resp.status_code == 413
    assert _alerts(db) == 0


def test_more_than_5000_findings_is_413(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    resp = client.post(URL, content=b"[" + b",".join([b"{}"] * 5001) + b"]", headers=_auth(token))
    assert resp.status_code == 413
    assert _alerts(db) == 0


def test_one_invalid_finding_rejects_the_whole_request(
    api: tuple[TestClient, Path, str],
) -> None:
    client, db, token = api
    items = _fixture()
    del items[2]["finding_info"]["uid"]
    resp = client.post(URL, json=items, headers=_auth(token))
    assert resp.status_code == 422
    errors = resp.json()["errors"]
    assert errors and all(e["index"] == 2 for e in errors)
    assert set(errors[0]) == {"index", "path", "message"}
    assert _alerts(db) == 0


@pytest.mark.parametrize("body", [b"{}", b"not json", b'"text"', b"null", b""])
def test_non_list_or_non_json_is_422(api: tuple[TestClient, Path, str], body: bytes) -> None:
    client, db, token = api
    resp = client.post(URL, content=body, headers=_auth(token))
    assert resp.status_code == 422
    assert _alerts(db) == 0


def test_empty_list_is_ok_and_creates_nothing(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    resp = client.post(URL, json=[], headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json() == {"created": 0, "unchanged": 0, "incidents_touched": []}
    assert _alerts(db) == 0


def test_script_tag_round_trips_unchanged(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    items = copy.deepcopy(_fixture())
    title = '<script>alert(1)</script>"><img onerror=x>'
    items[0]["finding_info"]["title"] = title
    assert client.post(URL, json=items, headers=_auth(token)).status_code == 200
    with closing(sqlite3.connect(db)) as conn:
        raw = conn.execute("SELECT raw_json FROM alerts WHERE rule = 'R05'").fetchone()[0]
    assert json.loads(raw)["finding_info"]["title"] == title


def test_non_utf8_body_is_422(api: tuple[TestClient, Path, str]) -> None:
    client, _, token = api
    resp = client.post(URL, content=b"\xff\xfe[", headers=_auth(token))
    assert resp.status_code == 422


def test_non_object_items_are_422(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    resp = client.post(URL, json=[1, "a", None], headers=_auth(token))
    assert resp.status_code == 422
    assert {e["index"] for e in resp.json()["errors"]} == {0, 1, 2}
    assert _alerts(db) == 0


def test_chunked_body_over_10_mb_is_413(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api

    def chunks() -> Iterator[bytes]:  # no Content-Length, so only the stream count can stop it
        for _ in range(11):
            yield b"x" * (1024 * 1024)

    resp = client.post(URL, content=chunks(), headers=_auth(token))
    assert resp.status_code == 413
    assert _alerts(db) == 0


def test_deeply_nested_json_is_422_not_500(api: tuple[TestClient, Path, str]) -> None:
    client, _, token = api
    resp = client.post(URL, content=b"[" * 1_000_000, headers=_auth(token))
    assert resp.status_code == 422


@pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Token abc", "bearer"])
def test_malformed_authorization_headers_are_401(
    api: tuple[TestClient, Path, str], header: str
) -> None:
    client, _, _ = api
    assert client.post(URL, json=[], headers={"Authorization": header}).status_code == 401


def test_scheme_is_case_insensitive(api: tuple[TestClient, Path, str]) -> None:
    client, _, token = api
    resp = client.post(URL, json=[], headers={"Authorization": f"bearer {token}"})
    assert resp.status_code == 200


def test_key_with_another_scope_is_401(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("UPDATE api_keys SET scope = 'admin'")
        conn.commit()
    assert client.post(URL, json=[], headers=_auth(token)).status_code == 401


def test_api_module_imports_on_its_own() -> None:
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-I", "-c", "import app.api"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr


def test_5000_findings_exactly_is_accepted(api: tuple[TestClient, Path, str]) -> None:
    client, db, token = api
    base = _fixture()[0]
    items = []
    for n in range(5000):
        item = copy.deepcopy(base)
        item["finding_info"]["uid"] = f"00000000-0000-4000-8000-{n:012d}"
        items.append(item)
    resp = client.post(URL, json=items, headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["created"] == 5000
    assert _alerts(db) == 5000


def test_store_failure_is_5xx_and_leaves_no_rows(
    api: tuple[TestClient, Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, db, token = api
    from app import ingest

    def boom(*_: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(ingest, "_insert_entities", boom)
    quiet = TestClient(main_mod.app, raise_server_exceptions=False)
    resp = quiet.post(URL, json=_fixture(), headers=_auth(token))
    assert resp.status_code == 500
    assert _alerts(db) == 0


def test_locked_database_is_503_with_retry_after(
    api: tuple[TestClient, Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db, token = api

    def locked(_: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("app.api.ingest_findings", lambda *a: locked(a))
    resp = client.post(URL, json=_fixture(), headers=_auth(token))
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "5"
    assert _alerts(db) == 0


def test_extra_spaces_after_bearer_are_tolerated(api: tuple[TestClient, Path, str]) -> None:
    client, _, token = api
    resp = client.post(URL, json=[], headers={"Authorization": f"Bearer   {token}"})
    assert resp.status_code == 200
