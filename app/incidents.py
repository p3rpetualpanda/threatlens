"""Write the correlation partition into incidents, honouring analyst state (spec 6.4).

Rules: resolved incidents are frozen (new linked alerts open a new incident that points back
through ``related_incident``); a touched incident never splits; incidents that one component
bridges merge into the oldest (touched first); ids of surviving incidents never change.
The caller owns the transaction: nothing is committed here.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .audit import record
from .correlate import Alert, partition
from .correlation_config import load_config
from .risk import load_risk_config, score

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
Spans = dict[str, tuple[datetime, datetime]]


@dataclass
class _Group:
    members: set[str] = field(default_factory=set)
    frozen: set[str] = field(default_factory=set)
    why: dict[str, str] = field(default_factory=dict)
    too_common: frozenset[str] = frozenset()


def _ms(value: Any) -> datetime | None:
    if not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OverflowError, ValueError, OSError):  # the schema only bounds the minimum
        return None


def _load_alerts(
    conn: sqlite3.Connection, environment: str
) -> tuple[list[Alert], dict[str, str], Spans]:
    entities: dict[str, set[tuple[str, str]]] = {}
    for r in conn.execute(
        "SELECT e.alert_id, e.kind, e.value FROM alert_entities e "
        "JOIN alerts a ON a.id = e.alert_id WHERE a.environment = ?",
        [environment],
    ):
        entities.setdefault(r["alert_id"], set()).add((r["kind"], r["value"]))
    alerts: list[Alert] = []
    titles: dict[str, str] = {}
    spans: Spans = {}
    for r in conn.execute(
        "SELECT id, rule, time, raw_json FROM alerts WHERE environment = ?", [environment]
    ):
        info = json.loads(r["raw_json"]).get("finding_info", {})
        fallback = datetime.fromisoformat(r["time"]) if r["time"] else _EPOCH
        first = _ms(info.get("first_seen_time")) or fallback
        last = max(first, _ms(info.get("last_seen_time")) or first)
        titles[r["id"]] = str(info.get("title") or r["rule"])
        spans[r["id"]] = (first, last)
        alerts.append(Alert(r["id"], r["rule"], first, last, frozenset(entities.get(r["id"], ()))))
    return alerts, titles, spans


def recorrelate(conn: sqlite3.Connection, environment: str, now: datetime) -> list[str]:
    """Re-partition one environment; return ids of incidents created or changed."""
    stamp = now.isoformat()
    alerts, titles, spans = _load_alerts(conn, environment)
    incidents = {
        r["id"]: r
        for r in conn.execute(
            "SELECT * FROM incidents WHERE environment = ? AND merged_into IS NULL", [environment]
        )
    }
    member_of: dict[str, str] = {}
    pinned: set[str] = set()
    for r in conn.execute(
        "SELECT ia.incident_id, ia.alert_id, ia.pinned FROM incident_alerts ia "
        "JOIN incidents i ON i.id = ia.incident_id "
        "WHERE i.environment = ? AND i.merged_into IS NULL",
        [environment],
    ):
        member_of[r["alert_id"]] = r["incident_id"]
        if r["pinned"]:
            pinned.add(r["alert_id"])
    frozen_alerts = {a for a, i in member_of.items() if incidents[i]["status"] == "resolved"}
    movable = {a.uid for a in alerts} - pinned - frozen_alerts

    groups = [
        _Group(
            set(c.uids & movable),
            {member_of[a] for a in c.uids & frozen_alerts},
            c.why,
            c.too_common,
        )
        for c in partition(alerts, load_config())
    ]
    groups = [g for g in _join_on_touched(groups, member_of, incidents) if g.members]
    groups.sort(key=lambda g: min(g.members))  # max() below keeps the first of equal scores

    # An untouched incident split across groups stays with the group holding most of it.
    best: dict[str, tuple[int, int]] = {}
    for k, g in enumerate(groups):
        for iid, n in Counter(member_of[a] for a in g.members if a in member_of).items():
            if iid not in best or n > best[iid][0]:
                best[iid] = (n, k)
    owner = {iid: k for iid, (_, k) in best.items()}

    changed: list[str] = []
    for k, g in enumerate(groups):
        mine = sorted(
            (i for i, o in owner.items() if o == k),
            key=lambda i: (not incidents[i]["touched"], incidents[i]["created_at"], i),
        )
        if mine:
            winner, losers = mine[0], mine[1:]
        else:
            winner, losers = str(uuid.uuid4()), []
            _insert_incident(conn, winner, environment, stamp)
            changed.append(winner)
        for loser in losers:
            _merge(conn, loser, winner, stamp, now)
        did_change = _sync(conn, winner, g, titles, spans, pinned, stamp) or bool(losers)
        if did_change and winner not in changed:
            changed.append(winner)
    return changed


def _join_on_touched(
    groups: list[_Group], member_of: dict[str, str], incidents: dict[str, sqlite3.Row]
) -> list[_Group]:
    """Groups sharing a touched incident become one, so a touched incident never splits."""
    touched = {i for i, r in incidents.items() if r["touched"]}
    out: list[_Group] = []
    for g in groups:
        mine = {member_of[a] for a in g.members if a in member_of} & touched
        for prev in [p for p in out if mine & {member_of.get(a) for a in p.members}]:
            out.remove(prev)
            g.members |= prev.members
            g.frozen |= prev.frozen
            g.why |= prev.why
            g.too_common |= prev.too_common
        out.append(g)
    return out


def _insert_incident(conn: sqlite3.Connection, iid: str, environment: str, stamp: str) -> None:
    conn.execute(
        "INSERT INTO incidents (id, environment, title, created_at, updated_at) "
        "VALUES (?, ?, '', ?, ?)",
        [iid, environment, stamp, stamp],
    )


def _merge(conn: sqlite3.Connection, loser: str, winner: str, stamp: str, now: datetime) -> None:
    lost = conn.execute(
        "SELECT l.owner AS owner, l.disposition AS disposition FROM incidents l, incidents w "
        "WHERE l.id = ? AND w.id = ? AND ((l.owner IS NOT NULL AND w.owner IS NOT NULL "
        "AND l.owner != w.owner) OR (l.disposition IS NOT NULL AND w.disposition IS NOT NULL "
        "AND l.disposition != w.disposition))",
        [loser, winner],
    ).fetchone()
    conn.execute(
        "UPDATE incident_alerts SET incident_id = ? WHERE incident_id = ?", [winner, loser]
    )
    conn.execute("UPDATE comments SET incident_id = ? WHERE incident_id = ?", [winner, loser])
    # a step both incidents have stays done if either had it done
    conn.execute(
        "UPDATE playbook_progress SET done = 1 WHERE incident_id = ? AND done = 0 AND step IN "
        "(SELECT step FROM playbook_progress WHERE incident_id = ? AND done = 1)",
        [winner, loser],
    )
    conn.execute(
        "UPDATE OR IGNORE playbook_progress SET incident_id = ? WHERE incident_id = ?",
        [winner, loser],
    )
    conn.execute("DELETE FROM playbook_progress WHERE incident_id = ?", [loser])
    # The winner keeps its own analyst state and takes whatever the loser had that it lacks.
    conn.execute(
        "UPDATE incidents SET "
        "owner = COALESCE(owner, (SELECT owner FROM incidents WHERE id = ?1)), "
        "disposition = COALESCE(disposition, (SELECT disposition FROM incidents WHERE id = ?1)), "
        "related_incident = COALESCE(related_incident, "
        "(SELECT related_incident FROM incidents WHERE id = ?1)), "
        "status = CASE WHEN status = 'new' THEN (SELECT status FROM incidents WHERE id = ?1) "
        "ELSE status END, "
        "touched = touched OR (SELECT touched FROM incidents WHERE id = ?1), "
        "updated_at = ?3 WHERE id = ?2",
        [loser, winner, stamp],
    )
    conn.execute(
        "UPDATE incidents SET merged_into = ?, updated_at = ? WHERE id = ?", [winner, stamp, loser]
    )
    detail: dict[str, Any] = {"merged": loser}
    if lost:  # the winner's value was kept; keep the loser's on record
        detail["dropped"] = {k: lost[k] for k in ("owner", "disposition") if lost[k]}
    record(conn, "system", "incident.merge", winner, detail, now)


def _sync(
    conn: sqlite3.Connection,
    iid: str,
    g: _Group,
    titles: dict[str, str],
    spans: Spans,
    pinned: set[str],
    stamp: str,
) -> bool:
    """Bring one incident's rows in line with its group; return whether anything changed."""
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", [iid]).fetchone()
    cur = {
        r["alert_id"]: r["why"]
        for r in conn.execute(
            "SELECT alert_id, why FROM incident_alerts WHERE incident_id = ?", [iid]
        )
    }
    desired = set(g.members) | (set(cur) & pinned)
    moved = False
    for a in set(cur) - desired:
        conn.execute("DELETE FROM incident_alerts WHERE incident_id = ? AND alert_id = ?", [iid, a])
        moved = True
    for a in desired - set(cur):
        # an alert leaving another untouched incident is moved, not duplicated
        conn.execute("DELETE FROM incident_alerts WHERE alert_id = ?", [a])
        conn.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id, why) VALUES (?, ?, ?)",
            [iid, a, g.why.get(a, "")],
        )
        moved = True
    for a in desired & set(cur):
        if a in g.why and cur[a] != g.why[a]:
            conn.execute(
                "UPDATE incident_alerts SET why = ? WHERE incident_id = ? AND alert_id = ?",
                [g.why[a], iid, a],
            )
    members = conn.execute(
        "SELECT a.severity, a.tactic FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
        "WHERE ia.incident_id = ?",
        [iid],
    ).fetchall()
    risk, factors = score(
        [m["severity"] for m in members],
        {m["tactic"] for m in members if m["tactic"]},
        load_risk_config(),
    )
    n = len(desired)
    first_alert = min(desired, key=lambda a: (spans[a][0], a))
    title = titles[first_alert] + (f" (+{n - 1} more)" if n > 1 else "")
    values = (
        row["title"] if row["touched"] and row["title"] else title,
        min(spans[a][0] for a in desired).isoformat(timespec="milliseconds"),
        max(spans[a][1] for a in desired).isoformat(timespec="milliseconds"),
        row["related_incident"] or (min(g.frozen) if g.frozen else None),
        json.dumps(sorted(g.too_common)),
        risk,
        json.dumps(factors),
    )
    same = values == (
        row["title"],
        row["first_seen"],
        row["last_seen"],
        row["related_incident"],
        row["too_common"],
        row["risk_score"],
        row["risk_factors"],
    )
    if same and not moved:
        return False
    conn.execute(
        "UPDATE incidents SET title = ?, first_seen = ?, last_seen = ?, related_incident = ?, "
        "too_common = ?, risk_score = ?, risk_factors = ?, updated_at = ? WHERE id = ?",
        [*values, stamp, iid],
    )
    return True
