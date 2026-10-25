from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path

_MIGRATION = re.compile(r"^(\d+)_.*\.sql$")


def _num(path: Path) -> int:
    m = _MIGRATION.match(path.name)
    if m is None:
        raise ValueError(f"not a numbered migration: {path.name}")
    return int(m.group(1))


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def _ordered(migrations_dir: Path) -> list[Path]:
    # key=_num raises on any .sql that is not NNN_name.sql (fail loud, don't skip);
    # the filename breaks same-number ties so the order is stable.
    return sorted(migrations_dir.glob("*.sql"), key=lambda p: (_num(p), p.name))


def migrate(db_path: Path, migrations_dir: Path | None = None) -> int:
    migrations_dir = migrations_dir or Path(__file__).parent / "migrations"
    if not migrations_dir.is_dir():
        raise RuntimeError(f"migrations directory not found: {migrations_dir}")
    scripts = _ordered(migrations_dir)
    if not scripts:
        raise RuntimeError(f"no migrations in {migrations_dir}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(db_path)) as conn:
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        for path in scripts:
            num = _num(path)
            if num <= current:
                continue
            # One transaction (SQLite DDL and user_version are transactional): a failure part
            # way leaves no half-applied schema; closing the connection rolls it back.
            body = path.read_text(encoding="utf-8")
            try:
                conn.executescript(f"BEGIN;\n{body}\nPRAGMA user_version={num};\nCOMMIT;")  # nosec
            except sqlite3.OperationalError:
                # Another process may have applied this one first (server start vs CLI).
                if int(conn.execute("PRAGMA user_version").fetchone()[0]) < num:
                    raise
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
