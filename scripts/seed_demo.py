"""Seed the demo database on first start: findings, assets, identities, one admin.

Usage: seed_demo.py DB FINDINGS CONFIG_DIR. Does nothing if the database already has a user, so a
container restart keeps its data and its password. The admin password is random and printed once.
"""

from __future__ import annotations

import os
import secrets
import sys
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path

from app.cli import main as threatlens
from app.db import connect, migrate

EMAIL = "demo@example.test"


def main(argv: Sequence[str]) -> int:
    db, findings, config = (Path(a) for a in argv)
    migrate(db)
    with closing(connect(db)) as conn:
        if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            print("demo database already seeded")
            return 0
    password = secrets.token_urlsafe(16)
    os.environ["THREATLENS_ADMIN_PASSWORD"] = password
    steps = [
        ["import", str(findings)],
        ["load-assets", str(config / "assets.csv")],
        ["load-identities", str(config / "identities.csv")],
        ["create-admin", EMAIL],
    ]
    for step in steps:
        if threatlens([*step, "--db", str(db)]) != 0:
            return 1
    print(f"sign in at http://127.0.0.1:8000/login  email: {EMAIL}  password: {password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
