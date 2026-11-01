"""The metrics page (viewer and up)."""

from __future__ import annotations

from contextlib import closing

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from . import config
from .db import connect
from .metrics import build
from .ui import _page, _viewer

router = APIRouter()


@router.get("/metrics", response_class=HTMLResponse, include_in_schema=False)
def metrics_page(request: Request) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    with closing(connect(config.DB_PATH)) as conn:
        return _page(request, "metrics.html", session, **build(conn))
