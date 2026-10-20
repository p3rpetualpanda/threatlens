from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod


@pytest.fixture()
def booted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Path]]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(main_mod, "_DB_PATH", db)
    with TestClient(main_mod.app) as client:  # context manager fires lifespan -> migrate()
        yield client, db


def test_app_boots_and_migrates(booted: tuple[TestClient, Path]) -> None:
    _, db = booted
    with closing(sqlite3.connect(db)) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "alerts", "incidents"} <= names


def test_health_returns_ok(booted: tuple[TestClient, Path]) -> None:
    client, _ = booted
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_fails_when_db_unusable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = tmp_path / "blocker"
    blocker.mkdir()  # a directory, not a file: sqlite cannot open it
    monkeypatch.setattr(main_mod, "_DB_PATH", blocker)
    client = TestClient(main_mod.app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 500


def test_health_fails_when_schema_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A fresh path with no file: sqlite auto-creates an empty DB on connect, so the
    # old SELECT 1 passed and reported "ok" with no schema at all.
    monkeypatch.setattr(main_mod, "_DB_PATH", tmp_path / "empty.db")
    client = TestClient(main_mod.app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 500
