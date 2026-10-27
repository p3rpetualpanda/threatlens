"""One-shot messages handed from a POST to the page it redirects to, keyed by session.

The redirect target stays a plain URL, so a refresh or a typed `?done=` cannot replay or fake
a message, and a one-time API token never rides in a URL. Rows are in SQLite, so several
workers and restarts are fine. A row lives 60 s and is deleted when read; nothing secret goes in
`value` (a new API token travels in a cookie instead, see app/admin_ui.py).
"""

from __future__ import annotations

import hashlib
import json
from contextlib import closing
from datetime import UTC, datetime, timedelta
from typing import Any

from . import config
from .db import connect

_TTL = timedelta(seconds=60)


def _key(session_key: str) -> str:
    return hashlib.sha256(session_key.encode()).hexdigest()


def put(session_key: str, kind: str, value: Any) -> None:
    now = datetime.now(UTC)
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("DELETE FROM flash WHERE at < ?", [(now - _TTL).isoformat()])
        conn.execute(
            "INSERT OR REPLACE INTO flash (session_key, kind, value, at) VALUES (?, ?, ?, ?)",
            [_key(session_key), kind, json.dumps(value), now.isoformat()],
        )
        conn.commit()


def pop(session_key: str, kind: str) -> Any | None:
    cutoff = (datetime.now(UTC) - _TTL).isoformat()
    with closing(connect(config.DB_PATH)) as conn:
        row = conn.execute(
            "DELETE FROM flash WHERE session_key = ? AND kind = ? RETURNING value, at",
            [_key(session_key), kind],
        ).fetchone()
        conn.commit()
    if row is None or row["at"] < cutoff:
        return None
    return json.loads(row["value"])
