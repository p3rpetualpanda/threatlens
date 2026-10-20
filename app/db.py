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
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def _ordered(migrations_dir: Path) -> list[Path]:
    files = [p for p in migrations_dir.glob("*.sql") if _MIGRATION.match(p.name)]
    return sorted(files, key=_num)


def migrate(db_path: Path, migrations_dir: Path | None = None) -> int:
    migrations_dir = migrations_dir or Path(__file__).parent / "migrations"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(db_path)) as conn:
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        for path in _ordered(migrations_dir):
            num = _num(path)
            if num <= current:
                continue
            conn.executescript(path.read_text(encoding="utf-8"))
            # num is an int from the filename; PRAGMA user_version has no parameterized form.
            conn.execute(f"PRAGMA user_version={num}")  # nosec
            conn.commit()
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
