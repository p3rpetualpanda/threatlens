from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(
    title="ThreatLens",
    description="Explainable blue-team detection and incident response. v2 in progress.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
