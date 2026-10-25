"""Append-only audit log with a hash chain.

Each row stores `hash = sha256(prev_hash + canonical_json(row))`, so editing or deleting any row
other than the newest breaks the chain from that point on. `verify` recomputes it.
shortcut: cutting rows off the tail is not detectable from the log alone; keep an offsite copy
of the latest hash if that matters.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Any

GENESIS = "0" * 64


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(prev: str, fields: dict[str, Any]) -> str:
    return hashlib.sha256((prev + _canonical(fields)).encode()).hexdigest()


def record(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target: str | None,
    detail: dict[str, Any] | None,
    now: datetime,
) -> None:
    """Add one row. Does not commit: it joins the caller's transaction, so a rolled-back change
    leaves no audit row. Outside a transaction it opens one, which takes the write lock before
    the last hash is read."""
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    last = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    row_id = 1 if last is None else int(last["id"]) + 1
    prev = GENESIS if last is None else str(last["hash"])
    fields = {
        "id": row_id,
        "at": now.isoformat(),
        "actor": actor,
        "action": action,
        "target": target,
        "detail": _canonical(detail) if detail is not None else None,
    }
    conn.execute(
        "INSERT INTO audit_log (id, at, actor, action, target, detail, prev_hash, hash) "
        "VALUES (:id, :at, :actor, :action, :target, :detail, :prev, :hash)",
        {**fields, "prev": prev, "hash": _hash(prev, fields)},
    )


def verify(conn: sqlite3.Connection) -> int | None:
    """Return the id of the first row that breaks the chain, or None if it is intact."""
    prev = GENESIS
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        fields = {k: row[k] for k in ("id", "at", "actor", "action", "target", "detail")}
        if row["prev_hash"] != prev or row["hash"] != _hash(prev, fields):
            return int(row["id"])
        prev = str(row["hash"])
    return None
