from __future__ import annotations

import sqlite3
from contextlib import closing, suppress
from pathlib import Path

from app.db import _ordered, connect, migrate


def test_migrate_creates_schema_and_version(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    assert migrate(db) == 1
    with closing(connect(db)) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for expected in (
        "users",
        "sessions",
        "api_keys",
        "environments",
        "alerts",
        "alert_entities",
        "incidents",
        "incident_alerts",
        "comments",
        "playbook_progress",
        "audit_log",
        "assets",
        "identities",
    ):
        assert expected in names


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    migrate(db)
    assert migrate(db) == 1  # second run applies nothing, no error


def test_orders_migrations_numerically(tmp_path: Path) -> None:
    d = tmp_path / "m"
    d.mkdir()
    for name in ("10_b.sql", "2_a.sql", "1_initial.sql"):
        (d / name).write_text("", encoding="utf-8")
    got = [p.name for p in _ordered(d)]
    assert got == ["1_initial.sql", "2_a.sql", "10_b.sql"]


def test_failed_migration_leaves_version_unchanged(tmp_path: Path) -> None:
    d = tmp_path / "m"
    d.mkdir()
    (d / "1_bad.sql").write_text("INSERT INTO does_not_exist VALUES (1);", encoding="utf-8")
    db = tmp_path / "t.db"
    with suppress(sqlite3.OperationalError):
        migrate(db, migrations_dir=d)
    with closing(connect(db)) as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 0


def test_failed_migration_after_success_keeps_last_good_version(tmp_path: Path) -> None:
    d = tmp_path / "m"
    d.mkdir()
    (d / "1_good.sql").write_text("CREATE TABLE t1 (id TEXT PRIMARY KEY);", encoding="utf-8")
    (d / "2_bad.sql").write_text("INSERT INTO does_not_exist VALUES (1);", encoding="utf-8")
    db = tmp_path / "t.db"
    with suppress(sqlite3.OperationalError):
        migrate(db, migrations_dir=d)
    with closing(connect(db)) as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 1
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "t1" in tables


def test_migrate_creates_parent_dir(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "deep" / "t.db"
    migrate(db)
    assert db.exists()


def test_wal_mode_is_persisted(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    migrate(db)
    with closing(connect(db)) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
