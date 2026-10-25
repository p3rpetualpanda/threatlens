"""`threatlens import FILE` and `threatlens create-api-key NAME`."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from .apikeys import create_api_key
from .audit import verify
from .contract import validate_findings
from .db import connect, migrate
from .ingest import ingest_findings
from .users import create_user

BATCH = 1_000
MAX_SHOWN = 10


def _default_db() -> Path:
    return Path(os.environ.get("THREATLENS_DB_PATH", "data/threatlens.db"))


def _read(path: Path) -> tuple[list[dict[str, object]], list[int]] | str:
    """Parse the whole file first; return (findings, their line numbers) or an error message."""
    try:
        text = path.read_text(encoding="utf-8-sig")  # PowerShell writes a BOM
    except (OSError, UnicodeDecodeError) as exc:
        return f"cannot read {path}: {exc}"
    findings: list[dict[str, object]] = []
    lines: list[int] = []
    # Split on \n only: splitlines() also cuts at U+2028/U+0085, legal inside JSON strings.
    for number, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (ValueError, RecursionError) as exc:
            return f"{path} line {number}: not valid JSON: {exc}"
        findings.append(item)
        lines.append(number)
    return findings, lines


def _import(path: Path, db: Path) -> int:
    parsed = _read(path)
    if isinstance(parsed, str):
        print(parsed, file=sys.stderr)
        return 1
    findings, lines = parsed
    errors = validate_findings(list(findings))
    if errors:
        for e in errors[:MAX_SHOWN]:
            print(
                f"{path} line {lines[e.index]}: {e.path or '(finding)'}: {e.message}",
                file=sys.stderr,
            )
        if len(errors) > MAX_SHOWN:
            print(f"... and {len(errors) - MAX_SHOWN} more errors", file=sys.stderr)
        print("nothing was imported", file=sys.stderr)
        return 1

    migrate(db)
    created = unchanged = 0
    try:
        with closing(connect(db)) as conn:
            for start in range(0, len(findings), BATCH):
                # Everything is validated, so only a database failure can stop between batches.
                result = ingest_findings(
                    conn, findings[start : start + BATCH], datetime.now(UTC), "cli"
                )
                created += result["created"]
                unchanged += result["unchanged"]
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        print(
            f"{created + unchanged} findings were already stored; run the import again to "
            "finish (it is safe to repeat)",
            file=sys.stderr,
        )
        return 1
    print(f"imported {len(findings)} findings: created {created}, unchanged {unchanged}")
    return 0


def _create_api_key(name: str, db: Path) -> int:
    try:
        migrate(db)
        with closing(connect(db)) as conn:
            token = create_api_key(conn, name, datetime.now(UTC), "cli")
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 1
    print(token)
    return 0


def _create_admin(email: str, db: Path) -> int:
    password = os.environ.get("THREATLENS_ADMIN_PASSWORD")
    if password is None:
        password = getpass.getpass("Admin password: ")
        if getpass.getpass("Repeat password: ") != password:
            print("passwords do not match", file=sys.stderr)
            return 1
    try:
        migrate(db)
        with closing(connect(db)) as conn:
            create_user(conn, email, password, "admin", datetime.now(UTC), "cli")
    except (ValueError, sqlite3.Error) as exc:
        print(f"cannot create admin: {exc}", file=sys.stderr)
        return 1
    print(f"created admin {email.strip().lower()}")
    return 0


def _audit_verify(db: Path) -> int:
    if not db.is_file():  # connect() would quietly create an empty database
        print(f"no database at {db}", file=sys.stderr)
        return 1
    try:
        with closing(connect(db)) as conn:
            bad = verify(conn)
            if bad is not None:
                print(f"audit chain broken at row {bad}", file=sys.stderr)
                return 1
            count = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 1
    print(f"audit chain ok ({count} rows)")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threatlens", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    imp = commands.add_parser("import", help="import a beacon findings JSON Lines file")
    imp.add_argument("file", type=Path)
    key = commands.add_parser("create-api-key", help="print a new ingest API key (shown once)")
    key.add_argument("name")
    admin = commands.add_parser(
        "create-admin", help="create an admin; password from $THREATLENS_ADMIN_PASSWORD or prompt"
    )
    admin.add_argument("email")
    audit = commands.add_parser("audit", help="audit log tools")
    audit.add_argument("action", choices=["verify"])
    for sub in (imp, key, admin, audit):
        sub.add_argument("--db", type=Path, default=None, help="default: $THREATLENS_DB_PATH")
    args = parser.parse_args(argv)
    db = args.db or _default_db()
    if args.command == "import":
        return _import(args.file, db)
    if args.command == "create-admin":
        return _create_admin(args.email, db)
    if args.command == "audit":
        return _audit_verify(db)
    return _create_api_key(args.name, db)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
