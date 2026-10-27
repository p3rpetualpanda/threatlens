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
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import config
from .accounts import AccountError, operator_change
from .anchor import AnchorError, append_anchor, check_anchor, generate_key, load_key
from .apikeys import create_api_key
from .audit import record, verify
from .contract import validate_findings
from .db import connect, migrate
from .enrich import load_assets, load_identities
from .incidents import rescore
from .ingest import ingest_findings
from .users import create_user

BATCH = 1_000
MAX_SHOWN = 10


def _default_db() -> Path:
    return Path(os.environ.get("THREATLENS_DB_PATH", config.DEFAULT_DB))


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


def _load_csv(kind: str, path: Path, db: Path) -> int:
    loader = load_assets if kind == "load-assets" else load_identities
    try:
        migrate(db)
        with closing(connect(db)) as conn:
            now = datetime.now(UTC)
            rows = loader(conn, path, now)
            conn.execute("BEGIN IMMEDIATE")
            try:
                changed = rescore(conn, now)
                record(conn, "cli", "incidents.rescore", None, {"changed": len(changed)}, now)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
    except (ValueError, sqlite3.Error) as exc:
        print(f"cannot load {path}: {exc}", file=sys.stderr)
        return 1
    print(f"loaded {rows} rows; re-scored {len(changed)} incidents")
    return 0


def _user_access(action: str, email: str, db: Path) -> int:
    if not db.is_file():
        print(f"no database at {db}", file=sys.stderr)
        return 1
    try:
        with closing(connect(db)) as conn:
            operator_change(conn, email, action, datetime.now(UTC))
    except AccountError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 1
    print(f"{action}: {email.strip().lower()}")
    return 0


def _anchor_paths(args: argparse.Namespace) -> tuple[Path | None, Path | None]:
    key = args.key_file or (Path(config.AUDIT_KEY_FILE) if config.AUDIT_KEY_FILE else None)
    anchor = args.anchor_file or (Path(config.AUDIT_ANCHOR) if config.AUDIT_ANCHOR else None)
    return key, anchor


def _audit_verify(db: Path, args: argparse.Namespace) -> int:
    if not db.is_file():  # connect() would quietly create an empty database
        print(f"no database at {db}", file=sys.stderr)
        return 1
    key_file, anchor_file = _anchor_paths(args)
    if (key_file is None) != (anchor_file is None):
        print("set both the audit key file and the anchor file, or neither", file=sys.stderr)
        return 1
    try:
        with closing(connect(db)) as conn:
            bad = verify(conn)
            if bad is not None:
                print(f"audit chain broken at row {bad}", file=sys.stderr)
                return 1
            count = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
            note = "no anchor configured"
            if key_file and anchor_file:
                problem = check_anchor(
                    conn,
                    load_key(key_file),
                    anchor_file,
                    datetime.now(UTC),
                    timedelta(hours=args.max_age),
                )
                if problem:
                    print(f"audit anchor check failed: {problem}", file=sys.stderr)
                    return 1
                note = "anchored"
    except AnchorError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 1
    print(f"audit chain ok ({count} rows); {note}")
    return 0


def _audit_anchor(db: Path, args: argparse.Namespace) -> int:
    key_file, anchor_file = _anchor_paths(args)
    if key_file is None or anchor_file is None:
        print("anchoring needs the key file and the anchor file", file=sys.stderr)
        return 1
    if not db.is_file():
        print(f"no database at {db}", file=sys.stderr)
        return 1
    try:
        with closing(connect(db)) as conn:
            if verify(conn) is not None:  # never sign a log that is already broken
                print("audit chain is broken; not anchoring", file=sys.stderr)
                return 1
            line = append_anchor(conn, load_key(key_file), anchor_file, datetime.now(UTC))
    except (AnchorError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 1
    print(f"anchored row {line['id']}")
    return 0


def _audit_keygen(path: Path | None) -> int:
    if path is None:
        print("keygen needs a path for the new key file", file=sys.stderr)
        return 1
    try:
        generate_key(path)
    except AnchorError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"wrote {path}; keep it out of git and off this database's backups")
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
    assets = commands.add_parser("load-assets", help="replace assets from a CSV")
    assets.add_argument("file", type=Path)
    idents = commands.add_parser("load-identities", help="replace identities from a CSV")
    idents.add_argument("file", type=Path)
    audit = commands.add_parser("audit", help="audit log tools")
    audit.add_argument("action", choices=["verify", "anchor", "keygen"])
    audit.add_argument("path", type=Path, nargs="?", help="keygen: where to write the key")
    audit.add_argument("--key-file", type=Path, help="default: $THREATLENS_AUDIT_KEY_FILE")
    audit.add_argument("--anchor-file", type=Path, help="default: $THREATLENS_AUDIT_ANCHOR")
    audit.add_argument("--max-age", type=float, default=24.0, help="hours; verify only")
    user = commands.add_parser("user", help="disable, enable or sign out an account")
    user.add_argument("action", choices=["disable", "enable", "revoke-sessions"])
    user.add_argument("email")
    for sub in (imp, key, admin, assets, idents, audit, user):
        sub.add_argument("--db", type=Path, default=None, help="default: $THREATLENS_DB_PATH")
    args = parser.parse_args(argv)
    db = args.db or _default_db()
    if args.command == "import":
        return _import(args.file, db)
    if args.command == "create-admin":
        return _create_admin(args.email, db)
    if args.command in ("load-assets", "load-identities"):
        return _load_csv(args.command, args.file, db)
    if args.command == "user":
        return _user_access(args.action, args.email, db)
    if args.command == "audit":
        if args.action == "keygen":
            return _audit_keygen(args.path)
        if args.action == "anchor":
            return _audit_anchor(db, args)
        return _audit_verify(db, args)
    return _create_api_key(args.name, db)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
