from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from .db import migrate

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
    return {"status": "ok"}
