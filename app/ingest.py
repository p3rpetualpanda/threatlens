"""Ingest validated contract v1 findings into SQLite.

The caller validates first (app.contract). Ingest is all-or-nothing: one transaction, rolled
back on any error. A known `finding_info.uid` is idempotent: only `beacon_status` and
`last_ingested_at` change. Correlation into incidents is M3, so `incidents_touched` stays [].
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any, TypedDict

_ENTITY_KINDS = {
    "hosts": "host",
    "users": "user",
    "src_ips": "src_ip",
    "dst_ips": "dst_ip",
    "processes": "process",
}


class IngestResult(TypedDict):
    created: int
    unchanged: int
    incidents_touched: list[str]


def ingest_findings(
    conn: sqlite3.Connection, findings: list[dict[str, Any]], now: datetime
) -> IngestResult:
    result: IngestResult = {"created": 0, "unchanged": 0, "incidents_touched": []}
    if not findings:
        return result
    stamp = now.isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        envs: set[str] = set()
        for finding in findings:
            created, env = _upsert(conn, finding, stamp)
            result["created" if created else "unchanged"] += 1
            envs.add(env)
        for env in sorted(envs):
            _touch_environment(conn, env, stamp)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return result


def _touch_environment(conn: sqlite3.Connection, name: str, stamp: str) -> None:
    conn.execute(
        "INSERT INTO environments (id, name, last_import_at) VALUES (?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET last_import_at = excluded.last_import_at",
        [str(uuid.uuid4()), name, stamp],
    )


def _upsert(conn: sqlite3.Connection, finding: dict[str, Any], stamp: str) -> tuple[bool, str]:
    """Insert a new alert or refresh a known one; return (created, environment it is stored in).

    A uid already stored under another environment keeps that environment, so the import is
    credited to the environment that owns the alert, never the one that re-sent it.
    """
    info = finding["finding_info"]
    unmapped = finding["unmapped"]
    existing = conn.execute(
        "UPDATE alerts SET beacon_status = ?, last_ingested_at = ? WHERE finding_info_uid = ? "
        "RETURNING environment",
        [unmapped["beacon_status"], stamp, info["uid"]],
    ).fetchone()
    if existing:
        return False, str(existing["environment"])
    attack = info["attacks"][0]
    alert_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO alerts (id, finding_info_uid, raw_json, time, severity, rule, technique, "
        "tactic, environment, beacon_status, last_ingested_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            alert_id,
            info["uid"],
            json.dumps(finding, separators=(",", ":")),
            datetime.fromtimestamp(finding["time"] / 1000, UTC).isoformat(timespec="milliseconds"),
            finding["severity"],
            info["analytic"]["uid"],
            attack["technique"]["uid"],
            attack["tactic"]["name"],
            unmapped["environment"],
            unmapped["beacon_status"],
            stamp,
            stamp,
        ],
    )
    _insert_entities(conn, alert_id, unmapped["entities"])
    return True, str(unmapped["environment"])


def _insert_entities(conn: sqlite3.Connection, alert_id: str, entities: dict[str, Any]) -> None:
    conn.executemany(
        "INSERT INTO alert_entities (id, alert_id, kind, value) VALUES (?, ?, ?, ?)",
        [
            (str(uuid.uuid4()), alert_id, kind, value)
            for key, kind in _ENTITY_KINDS.items()
            for value in entities[key]
        ],
    )
