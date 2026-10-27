"""JSON routes for analyst actions on incidents; the rules live in app.workflow."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field

from . import config, workflow
from .auth import require_role
from .db import connect
from .sessions import Session

router = APIRouter(prefix="/api/v1/incidents/{incident_id}")
IncidentId = Annotated[str, Path(max_length=64)]


class AssignBody(BaseModel):
    owner: str | None = Field(max_length=254)


class StatusBody(BaseModel):
    status: str = Field(max_length=20)


class DispositionBody(BaseModel):
    disposition: str | None = Field(max_length=30)


class CommentBody(BaseModel):
    body: str = Field(max_length=workflow.MAX_COMMENT + 1000)


class MergeBody(BaseModel):
    into: str = Field(max_length=64)


class SplitBody(BaseModel):
    alerts: list[str] = Field(max_length=500)


def _run(act: Callable[[Any, datetime], dict[str, Any]]) -> dict[str, Any]:
    """One write transaction around a service call; its errors become HTTP errors."""
    now = datetime.now(UTC)
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            out = act(conn, now)
            conn.commit()
        except workflow.WorkflowError as exc:
            conn.rollback()
            raise HTTPException(exc.status, exc.message) from exc
        except BaseException:
            conn.rollback()
            raise
    return out


@router.post("/take")
def take(incident_id: IncidentId, s: Session = Depends(require_role("analyst"))) -> dict[str, Any]:  # noqa: B008
    return _run(lambda c, now: workflow.take(c, s.user, incident_id, now))


@router.post("/assign")
def assign(
    incident_id: IncidentId,
    body: AssignBody,
    s: Session = Depends(require_role("lead")),  # noqa: B008
) -> dict[str, Any]:
    return _run(lambda c, now: workflow.assign(c, s.user, incident_id, body.owner, now))


@router.post("/status")
def status(
    incident_id: IncidentId,
    body: StatusBody,
    s: Session = Depends(require_role("analyst")),  # noqa: B008
) -> dict[str, Any]:
    return _run(lambda c, now: workflow.set_status(c, s.user, incident_id, body.status, now))


@router.post("/disposition")
def disposition(
    incident_id: IncidentId,
    body: DispositionBody,
    s: Session = Depends(require_role("analyst")),  # noqa: B008
) -> dict[str, Any]:
    return _run(
        lambda c, now: workflow.set_disposition(c, s.user, incident_id, body.disposition, now)
    )


@router.post("/comments")
def comment(
    incident_id: IncidentId,
    body: CommentBody,
    s: Session = Depends(require_role("analyst")),  # noqa: B008
) -> dict[str, Any]:
    return _run(lambda c, now: workflow.add_comment(c, s.user, incident_id, body.body, now))


@router.post("/merge")
def merge(
    incident_id: IncidentId,
    body: MergeBody,
    s: Session = Depends(require_role("lead")),  # noqa: B008
) -> dict[str, Any]:
    """Merge this incident into ``into``; the other one survives."""
    return _run(lambda c, now: workflow.merge(c, s.user, incident_id, body.into, now))


@router.post("/split")
def split(
    incident_id: IncidentId,
    body: SplitBody,
    s: Session = Depends(require_role("lead")),  # noqa: B008
) -> dict[str, Any]:
    return _run(lambda c, now: workflow.split(c, s.user, incident_id, body.alerts, now))
