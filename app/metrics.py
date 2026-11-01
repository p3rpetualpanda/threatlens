"""Read-only numbers for the metrics page (spec 6.7 item 5). All counts skip merged-away incidents.

MTTA needs no stored "first owner" time: the append-only audit log has it (`incident.take`, or
`incident.assign` to a real owner). shortcut: a mean, not a median, so one old incident skews it;
upgrade if the page is used to judge a team.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any


def _mean_hours(pairs: list[tuple[str, str]]) -> float | None:
    secs = []
    for a, b in pairs:
        try:
            d = (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()
        except (TypeError, ValueError):  # mixed naive/aware or non-ISO text: skip, don't 500
            continue
        if d >= 0:  # a negative span is bad data, not a fast response
            secs.append(d)
    return round(sum(secs) / len(secs) / 3600, 1) if secs else None


def build(conn: sqlite3.Connection) -> dict[str, Any]:
    # only alerts that sit in a live incident, so both sides of the ratio cover the same set
    alerts = conn.execute(
        "SELECT COUNT(*) FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id "
        "WHERE i.merged_into IS NULL"
    ).fetchone()[0]
    incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE merged_into IS NULL").fetchone()[
        0
    ]
    mtta = conn.execute(
        "SELECT i.created_at, MIN(a.at) FROM incidents i JOIN audit_log a ON a.target = i.id "
        "AND (a.action = 'incident.take' "
        "OR (a.action = 'incident.assign' AND json_valid(a.detail) "
        "AND json_extract(a.detail, '$.to') IS NOT NULL)) "
        "WHERE i.merged_into IS NULL GROUP BY i.id"
    ).fetchall()
    mttr = conn.execute(
        "SELECT created_at, resolved_at FROM incidents WHERE merged_into IS NULL "
        "AND status = 'resolved' AND resolved_at IS NOT NULL"
    ).fetchall()
    rules = []
    for r in conn.execute(
        "SELECT a.rule, COUNT(*) AS alerts, "
        "COALESCE(SUM(i.status = 'resolved' "
        "AND i.disposition = 'true_positive'), 0) AS true_positive, "
        "COALESCE(SUM(i.status = 'resolved' "
        "AND i.disposition = 'benign_true_positive'), 0) AS benign, "
        "COALESCE(SUM(i.status = 'resolved' "
        "AND i.disposition = 'false_positive'), 0) AS false_positive "
        "FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id "
        "JOIN alerts a ON a.id = ia.alert_id WHERE i.merged_into IS NULL "
        "GROUP BY a.rule ORDER BY a.rule"
    ):
        decided = r["true_positive"] + r["benign"] + r["false_positive"]
        rules.append(
            {
                **dict(r),
                "decided": decided,
                "fp_rate": r["false_positive"] / decided if decided else None,
            }
        )
    return {
        "alerts": alerts,
        "incidents": incidents,
        "reduction": round(alerts / incidents, 1) if incidents else None,
        "mtta_hours": _mean_hours([(r[0], r[1]) for r in mtta]),
        "unacknowledged": incidents - len(mtta),  # MTTA only averages the acknowledged ones
        "mttr_hours": _mean_hours([(r[0], r[1]) for r in mttr]),
        "rules": rules,
    }
