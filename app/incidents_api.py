"""Read-only incident endpoints for any logged-in role: list, and one incident with its alerts."""

from __future__ import annotations

import json
from contextlib import closing
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from . import attack, config
from .auth import require_role
from .db import connect
from .risk import label, load_risk_config

router = APIRouter(prefix="/api/v1")


@router.get("/incidents", dependencies=[Depends(require_role("viewer"))])
def list_incidents(
    environment: Annotated[str | None, Query(max_length=200)] = None,
    status: Literal["new", "in_progress", "resolved"] | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    with closing(connect(config.DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT i.id, i.environment, i.title, i.status, i.risk_score, i.first_seen, "
            "i.last_seen, "
            "(SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count "
            "FROM incidents i WHERE i.merged_into IS NULL "
            "AND (?1 IS NULL OR i.environment = ?1) AND (?2 IS NULL OR i.status = ?2) "
            "ORDER BY i.last_seen DESC, i.id LIMIT ?3",
            [environment, status, limit],
        ).fetchall()
    return {"incidents": [dict(r) for r in rows]}


@router.get("/incidents/{incident_id}", dependencies=[Depends(require_role("viewer"))])
def get_incident(incident_id: Annotated[str, Path(max_length=64)]) -> dict[str, Any]:
    with closing(connect(config.DB_PATH)) as conn:
        row = conn.execute(
            "SELECT id, environment, title, status, disposition, owner, risk_score, first_seen, "
            "last_seen, related_incident, merged_into, touched, too_common, risk_factors "
            "FROM incidents WHERE id = ?",
            [incident_id],
        ).fetchone()
        if row is None:
            raise HTTPException(404, "no such incident")
        members = conn.execute(
            "SELECT a.finding_info_uid AS uid, a.rule, a.severity, a.technique, a.time, ia.why, "
            "ia.pinned "
            "FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id "
            "WHERE ia.incident_id = ? ORDER BY a.time, a.finding_info_uid",
            [incident_id],
        ).fetchall()
    folded: dict[str, dict[str, Any]] = {}
    for m in members:  # same rule repeated: one row with a count, the earliest alert explains it
        entry = folded.setdefault(
            m["rule"],
            {"rule": m["rule"], "severity": m["severity"], "why": m["why"], "count": 0, "uids": []},
        )
        entry["count"] += 1
        entry["uids"].append(m["uid"])
    return {
        **dict(row),
        "too_common": json.loads(row["too_common"]),
        "risk_factors": json.loads(row["risk_factors"] or "[]"),
        "risk_label": label(row["risk_score"] or 0, load_risk_config()),
        "techniques": [
            attack.describe(t) for t in sorted({m["technique"] for m in members if m["technique"]})
        ],
        "attack_version": attack.version(),
        "alert_count": len(members),
        "alerts": list(folded.values()),
    }
