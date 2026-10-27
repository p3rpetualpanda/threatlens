"""Analyst actions on incidents (spec 6.1 roles, 6.7): take, assign, status, disposition,
comment, merge, split. One service layer for the JSON API and, later, the HTML views.

Rules: an analyst works only incidents they own (take an unowned one first); a lead may act on
any incident, assign, merge and split. A resolved incident needs a disposition, and changing it
means reopening first. Every action marks the incident ``touched`` (correlation never splits it)
and writes an audit row. The caller owns the transaction: nothing is committed here.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime
from typing import Any

from .audit import record
from .incidents import _merge, refresh
from .users import ROLES, User

STATUSES = ("new", "in_progress", "resolved")
DISPOSITIONS = ("true_positive", "benign_true_positive", "false_positive")
MAX_COMMENT = 5000


class WorkflowError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _is_lead(user: User) -> bool:
    return ROLES.index(user.role) >= ROLES.index("lead")


def _load(conn: sqlite3.Connection, iid: str) -> sqlite3.Row:
    row: sqlite3.Row | None = conn.execute("SELECT * FROM incidents WHERE id = ?", [iid]).fetchone()
    if row is None:
        raise WorkflowError(404, "no such incident")
    if row["merged_into"]:
        raise WorkflowError(409, f"incident was merged into {row['merged_into']}")
    return row


def _own(user: User, row: sqlite3.Row) -> None:
    if not _is_lead(user) and row["owner"] != user.id:
        raise WorkflowError(403, "only the owner or a lead can change this incident")


def _state(conn: sqlite3.Connection, iid: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT id, status, disposition, owner, resolved_at FROM incidents WHERE id = ?", [iid]
    ).fetchone()
    return dict(row)


def _update(conn: sqlite3.Connection, iid: str, now: datetime, **changes: Any) -> None:
    """Apply the given owner/status/disposition/resolved_at changes and mark it touched."""
    cur = conn.execute(
        "SELECT owner, status, disposition, resolved_at FROM incidents WHERE id = ?", [iid]
    ).fetchone()
    new = {**dict(cur), **changes}
    conn.execute(
        "UPDATE incidents SET owner = ?, status = ?, disposition = ?, resolved_at = ?, "
        "touched = 1, updated_at = ? WHERE id = ?",
        [new["owner"], new["status"], new["disposition"], new["resolved_at"], now.isoformat(), iid],
    )


def take(conn: sqlite3.Connection, user: User, iid: str, now: datetime) -> dict[str, Any]:
    row = _load(conn, iid)
    if row["owner"] is not None:
        raise WorkflowError(409, "incident already has an owner")
    if row["status"] == "resolved":
        raise WorkflowError(409, "incident is resolved; reopen it first")
    _update(conn, iid, now, owner=user.id, status="in_progress")
    record(conn, user.email, "incident.take", iid, None, now)
    return _state(conn, iid)


def assign(
    conn: sqlite3.Connection, user: User, iid: str, owner_email: str | None, now: datetime
) -> dict[str, Any]:
    row = _load(conn, iid)
    if not _is_lead(user):
        raise WorkflowError(403, "only a lead can assign")
    owner_id = None
    if owner_email is not None:
        target = conn.execute(
            "SELECT id, role FROM users WHERE email = ?", [owner_email.strip().lower()]
        ).fetchone()
        if target is None or ROLES.index(target["role"]) < ROLES.index("analyst"):
            raise WorkflowError(422, "owner must be an existing analyst, lead or admin")
        owner_id = target["id"]
    if row["status"] == "resolved":
        raise WorkflowError(409, "incident is resolved; reopen it first")
    status = "in_progress" if owner_id else "new"  # unassigning sends it back to the queue
    _update(conn, iid, now, owner=owner_id, status=status)
    record(conn, user.email, "incident.assign", iid, {"from": row["owner"], "to": owner_id}, now)
    return _state(conn, iid)


def set_status(
    conn: sqlite3.Connection, user: User, iid: str, status: str, now: datetime
) -> dict[str, Any]:
    row = _load(conn, iid)
    _own(user, row)
    if status not in STATUSES:
        raise WorkflowError(422, f"status must be one of {', '.join(STATUSES)}")
    if status == row["status"]:
        raise WorkflowError(409, f"incident is already {status}")
    if status == "resolved":
        if row["disposition"] is None:
            raise WorkflowError(409, "set a disposition before resolving")
        _update(conn, iid, now, status="resolved", resolved_at=now.isoformat())
        cascaded = conn.execute(  # an alert the analyst already judged keeps its own disposition
            "UPDATE alerts SET disposition = ? WHERE disposition IS NULL AND id IN "
            "(SELECT alert_id FROM incident_alerts WHERE incident_id = ?)",
            [row["disposition"], iid],
        ).rowcount
    else:
        cascaded = 0
        if status == "new" and row["owner"] is not None:
            raise WorkflowError(409, "an owned incident cannot go back to new; unassign it")
        if row["status"] == "resolved" and not _is_lead(user):
            raise WorkflowError(403, "only a lead can reopen a resolved incident")
        if status == "in_progress" and row["owner"] is None:
            raise WorkflowError(409, "take or assign the incident first")
        _update(conn, iid, now, status=status, resolved_at=None)
    detail = {"from": row["status"], "to": status, "alerts_stamped": cascaded}
    record(conn, user.email, "incident.status", iid, detail, now)
    return _state(conn, iid)


def set_disposition(
    conn: sqlite3.Connection, user: User, iid: str, disposition: str | None, now: datetime
) -> dict[str, Any]:
    row = _load(conn, iid)
    _own(user, row)
    if disposition is not None and disposition not in DISPOSITIONS:
        raise WorkflowError(422, f"disposition must be one of {', '.join(DISPOSITIONS)}")
    if row["status"] == "resolved":
        raise WorkflowError(409, "incident is resolved; reopen it to change the disposition")
    _update(conn, iid, now, disposition=disposition)
    if row["disposition"] is not None:  # alerts stamped by an earlier resolve follow the change
        conn.execute(
            "UPDATE alerts SET disposition = ? WHERE disposition = ? AND id IN "
            "(SELECT alert_id FROM incident_alerts WHERE incident_id = ?)",
            [disposition, row["disposition"], iid],
        )
    detail = {"from": row["disposition"], "to": disposition}
    record(conn, user.email, "incident.disposition", iid, detail, now)
    return _state(conn, iid)


def add_comment(
    conn: sqlite3.Connection, user: User, iid: str, body: str, now: datetime
) -> dict[str, Any]:
    _load(conn, iid)
    text = body.strip()
    if not text or len(text) > MAX_COMMENT:
        raise WorkflowError(422, f"comment must be 1 to {MAX_COMMENT} characters")
    cid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO comments (id, incident_id, author, body, created_at) VALUES (?, ?, ?, ?, ?)",
        [cid, iid, user.email, text, now.isoformat()],
    )
    record(conn, user.email, "incident.comment", iid, {"comment": cid}, now)
    return {"id": cid, "incident_id": iid}


def merge(
    conn: sqlite3.Connection, user: User, loser: str, into: str, now: datetime
) -> dict[str, Any]:
    if not _is_lead(user):
        raise WorkflowError(403, "only a lead can merge")
    if loser == into:
        raise WorkflowError(422, "cannot merge an incident into itself")
    a, b = _load(conn, loser), _load(conn, into)
    if a["environment"] != b["environment"]:
        raise WorkflowError(422, "incidents are in different environments")
    if "resolved" in (a["status"], b["status"]):
        raise WorkflowError(409, "a resolved incident cannot be merged; reopen it first")
    stamp = now.isoformat()
    _merge(conn, loser, into, stamp, now, actor=user.email)
    _update(conn, into, now)
    refresh(conn, into, stamp)
    return _state(conn, into)


def split(
    conn: sqlite3.Connection, user: User, iid: str, uids: list[str], now: datetime
) -> dict[str, Any]:
    """Move the alerts with these finding uids into a new incident and pin them there."""
    if not _is_lead(user):
        raise WorkflowError(403, "only a lead can split")
    row = _load(conn, iid)
    if row["status"] == "resolved":
        raise WorkflowError(409, "incident is resolved; reopen it first")
    wanted = set(uids)
    members = {
        r["finding_info_uid"]: r["id"]
        for r in conn.execute(
            "SELECT a.id, a.finding_info_uid FROM incident_alerts ia "
            "JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = ?",
            [iid],
        )
    }
    if not wanted or not wanted <= members.keys():
        raise WorkflowError(422, "pick alerts that belong to this incident")
    if wanted == members.keys():
        raise WorkflowError(422, "leave at least one alert in the original incident")
    new_id, stamp = str(uuid.uuid4()), now.isoformat()
    conn.execute(
        "INSERT INTO incidents (id, environment, title, touched, created_at, updated_at) "
        "VALUES (?, ?, '', 1, ?, ?)",
        [new_id, row["environment"], stamp, stamp],
    )
    for uid in wanted:
        conn.execute(
            "UPDATE incident_alerts SET incident_id = ?, pinned = 1 "
            "WHERE incident_id = ? AND alert_id = ?",
            [new_id, iid, members[uid]],
        )
    _update(conn, iid, now)
    refresh(conn, iid, stamp)
    refresh(conn, new_id, stamp)
    detail = {"new_incident": new_id, "alerts": len(wanted)}
    record(conn, user.email, "incident.split", iid, detail, now)
    return _state(conn, new_id)
