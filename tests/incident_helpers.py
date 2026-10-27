"""Helpers shared by the incident tests: insert alerts directly and run recorrelate."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from app.incidents import recorrelate

T0 = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


def add(
    conn: sqlite3.Connection,
    uid: str,
    minutes: int,
    host: str | None = None,
    user: str | None = None,
    env: str = "e",
    rule: str = "R01",
) -> str:
    start = T0 + timedelta(minutes=minutes)
    raw = {
        "finding_info": {
            "title": f"Title {rule}",
            "first_seen_time": int(start.timestamp() * 1000),
            "last_seen_time": int(start.timestamp() * 1000),
        }
    }
    conn.execute(
        "INSERT INTO alerts (id, finding_info_uid, raw_json, time, severity, rule, environment, "
        "created_at) VALUES (?, ?, ?, ?, 'Medium', ?, ?, ?)",
        [uid, uid, json.dumps(raw), start.isoformat(), rule, env, NOW.isoformat()],
    )
    for kind, value in (("host", host), ("user", user)):
        if value:
            conn.execute(
                "INSERT INTO alert_entities (id, alert_id, kind, value) VALUES (?, ?, ?, ?)",
                [str(uuid.uuid4()), uid, kind, value],
            )
    return uid


def run(conn: sqlite3.Connection, env: str = "e", now: datetime = NOW) -> list[str]:
    conn.commit()  # close the implicit transaction the setup inserts opened
    conn.execute("BEGIN IMMEDIATE")
    try:
        out = recorrelate(conn, env, now)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return out
