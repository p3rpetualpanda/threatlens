from __future__ import annotations

import logging
import sqlite3
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import config
from .admin_ui import router as admin_ui_router
from .api import router as ingest_router
from .auth import router as auth_router
from .db import connect, migrate
from .incidents_api import router as incidents_router
from .ui import router as ui_router
from .ui_actions import router as ui_actions_router
from .workflow_api import router as workflow_router

_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
_NO_CSP_PATHS = {"/docs", "/redoc"}  # Swagger UI and ReDoc load scripts from a CDN
_LOGIN_PATHS = {"/api/v1/login", "/login"}
_MAX_LOGIN_BYTES = 4096
_log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    migrate(config.DB_PATH)
    yield


app = FastAPI(
    title="ThreatLens",
    description="Explainable blue-team detection and incident response. v2 in progress.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # shortcut: trusts Content-Length, so a chunked body skips this cap; put a body limit on the
    # reverse proxy before exposing the login route.
    declared = request.headers.get("content-length", "")
    if request.url.path in _LOGIN_PATHS and declared.isdigit() and int(declared) > _MAX_LOGIN_BYTES:
        response: Response = JSONResponse({"detail": "request body too large"}, status_code=413)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "same-origin"  # no-referrer makes browsers send Origin: null on form posts
    )
    response.headers["Cache-Control"] = "no-store"
    if request.url.path not in _NO_CSP_PATHS:
        response.headers["Content-Security-Policy"] = _CSP
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.exception_handler(sqlite3.OperationalError)
async def database_busy(request: Request, exc: sqlite3.OperationalError) -> JSONResponse:
    if "locked" in str(exc) or "busy" in str(exc):
        return JSONResponse(
            {"detail": "database is busy, retry"}, status_code=503, headers={"Retry-After": "5"}
        )
    _log.error("database error on %s", request.url.path, exc_info=exc)
    return JSONResponse({"detail": "database error"}, status_code=500)


app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(workflow_router)
app.include_router(ui_router)
app.include_router(ui_actions_router)
app.include_router(admin_ui_router)


@app.get("/health")
def health() -> dict[str, str]:
    with closing(connect(config.DB_PATH)) as conn:
        # user_version >= 1 means a migration ran. SELECT 1 alone would pass on a
        # brand-new empty DB, because sqlite auto-creates the file on connect.
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < 1:
            raise RuntimeError("schema missing: no migrations applied")
    return {"status": "ok"}
