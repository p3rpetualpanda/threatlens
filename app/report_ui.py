"""Incident report routes: a printable HTML page and a Markdown download (viewer and up)."""

from __future__ import annotations

from contextlib import closing
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, RedirectResponse

from . import config
from .db import connect
from .report import build, to_markdown
from .ui import _page, _viewer

router = APIRouter()


def _facts(incident_id: str) -> dict | None:  # type: ignore[type-arg]
    with closing(connect(config.DB_PATH)) as conn:
        return build(conn, incident_id)


@router.get("/incidents/{incident_id}/report", response_class=HTMLResponse, include_in_schema=False)
def report_page(
    request: Request, incident_id: Annotated[str, PathParam(max_length=64)]
) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    try:
        facts = _facts(incident_id)
    except HTTPException as exc:
        return _page(request, "error.html", session, exc.status_code, message=exc.detail)
    if facts is None:
        return _page(request, "error.html", session, 404, message="no such incident")
    return _page(request, "report.html", session, **facts)


@router.get("/incidents/{incident_id}/report.md", include_in_schema=False)
def report_markdown(
    request: Request, incident_id: Annotated[str, PathParam(max_length=64)]
) -> Response:
    if _viewer(request) is None:
        return RedirectResponse("/login", status_code=303)
    try:
        facts = _facts(incident_id)
    except HTTPException as exc:
        return Response(exc.detail, status_code=exc.status_code, media_type="text/plain")
    if facts is None:
        return Response("no such incident", status_code=404, media_type="text/plain")
    return Response(
        to_markdown(facts),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="incident-report.md"'},
    )
