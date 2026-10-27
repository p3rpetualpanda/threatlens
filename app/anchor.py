"""Keyed anchors for the audit log: a copy of the newest row hash, signed with a key that lives
outside the database and written to an append-only file that is shipped off the machine.

The hash chain alone has no secret, so someone holding the database file can rewrite it and
recompute every hash. An anchor line `{id, hash, at, mac}` pins row `id` to `hash`; the MAC means
the line cannot be forged without the key, and the offsite copy means it cannot be quietly cut.
shortcut: rows added after the newest anchor rest on the unkeyed chain until the next anchor;
run `threatlens audit anchor` from a scheduler (hourly) to keep that window short.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path


class AnchorError(Exception):
    """A problem with the key or anchor file itself (not a tamper finding)."""


def generate_key(path: Path) -> None:
    """Write 32 random bytes as hex; never overwrite. Owner-only where the OS allows it."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AnchorError(f"{path} exists; refusing to overwrite a key") from None
    except OSError as exc:
        raise AnchorError(f"cannot write {path}: {exc}") from exc
    with os.fdopen(fd, "w") as fh:
        fh.write(secrets.token_hex(32) + "\n")


def load_key(path: Path) -> bytes:
    try:
        text = path.read_text().strip()
    except OSError as exc:
        raise AnchorError(f"cannot read key file {path}: {exc}") from exc
    try:
        key = bytes.fromhex(text)
    except ValueError:
        key = b""
    if len(text) != 64 or len(key) != 32:
        raise AnchorError(f"key file {path} must hold 64 hex characters")
    return key


def _mac(key: bytes, row_id: int, row_hash: str, at: str) -> str:
    return hmac.new(key, f"{row_id}:{row_hash}:{at}".encode(), sha256).hexdigest()


def append_anchor(
    conn: sqlite3.Connection, key: bytes, path: Path, now: datetime
) -> dict[str, object]:
    """Sign the newest row and append one line, flushed to disk."""
    row = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        raise AnchorError("the audit log is empty; nothing to anchor")
    at = now.isoformat()
    line: dict[str, object] = {
        "id": row["id"],
        "hash": row["hash"],
        "at": at,
        "mac": _mac(key, row["id"], row["hash"], at),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(json.dumps(line, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return line


def check_anchor(
    conn: sqlite3.Connection, key: bytes, path: Path, now: datetime, max_age: timedelta
) -> str | None:
    """None when every anchor is genuine and still matches the log, else a one-line reason."""
    try:
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    except OSError as exc:
        return f"cannot read anchor file {path}: {exc}"
    if not lines:
        return "anchor file is empty"
    stamps: list[datetime] = []
    for n, text in enumerate(lines, 1):
        try:
            entry = json.loads(text)
            row_id, row_hash, at, mac = entry["id"], entry["hash"], entry["at"], entry["mac"]
            ok = (
                isinstance(row_id, int)
                and isinstance(row_hash, str)
                and isinstance(at, str)
                and isinstance(mac, str)
                and hmac.compare_digest(mac, _mac(key, row_id, row_hash, at))
            )
            stamp = datetime.fromisoformat(at)
        except (ValueError, KeyError, TypeError):
            ok = False
        if not ok:
            return f"anchor line {n} is malformed or its MAC is wrong"
        found = conn.execute("SELECT hash FROM audit_log WHERE id = ?", [row_id]).fetchone()
        if found is None:
            return f"anchored row {row_id} is missing from the log"
        if found["hash"] != row_hash:
            return f"anchored row {row_id} has changed"
        stamps.append(stamp)
    if now - max(stamps) > max_age:
        return f"newest anchor is older than {max_age}"
    return None
