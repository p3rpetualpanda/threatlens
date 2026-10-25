from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI

from . import config
from .api import router
from .db import connect, migrate


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


app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    with closing(connect(config.DB_PATH)) as conn:
        # user_version >= 1 means a migration ran. SELECT 1 alone would pass on a
        # brand-new empty DB, because sqlite auto-creates the file on connect.
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < 1:
            raise RuntimeError("schema missing: no migrations applied")
    return {"status": "ok"}
