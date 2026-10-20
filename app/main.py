from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, closing
from pathlib import Path

from fastapi import FastAPI

from .db import connect, migrate

_DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", "data/threatlens.db"))


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    migrate(_DB_PATH)
    yield


app = FastAPI(
    title="ThreatLens",
    description="Explainable blue-team detection and incident response. v2 in progress.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    with closing(connect(_DB_PATH)) as conn:
        # user_version >= 1 means a migration ran. SELECT 1 alone would pass on a
        # brand-new empty DB, because sqlite auto-creates the file on connect.
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < 1:
            raise RuntimeError("schema missing: no migrations applied")
    return {"status": "ok"}
