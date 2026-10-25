from __future__ import annotations

import sqlite3
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import config
from .api import router as ingest_router
from .auth import router as auth_router
from .db import connect, migrate

_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
_NO_CSP_PATHS = {"/docs", "/redoc"}  # Swagger UI and ReDoc load scripts from a CDN


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
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if request.url.path not in _NO_CSP_PATHS:
        response.headers["Content-Security-Policy"] = _CSP
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.exception_handler(sqlite3.OperationalError)
async def database_busy(_: Request, exc: sqlite3.OperationalError) -> JSONResponse:
    if "locked" in str(exc) or "busy" in str(exc):
        return JSONResponse(
            {"detail": "database is busy, retry"}, status_code=503, headers={"Retry-After": "5"}
        )
    return JSONResponse({"detail": "database error"}, status_code=500)


app.include_router(ingest_router)
app.include_router(auth_router)


@app.get("/health")
def health() -> dict[str, str]:
    with closing(connect(config.DB_PATH)) as conn:
        # user_version >= 1 means a migration ran. SELECT 1 alone would pass on a
        # brand-new empty DB, because sqlite auto-creates the file on connect.
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < 1:
            raise RuntimeError("schema missing: no migrations applied")
    return {"status": "ok"}
