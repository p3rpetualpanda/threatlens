"""POST /api/v1/findings: authenticated, validated, all-or-nothing import of beacon findings."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import config
from .apikeys import check_api_key
from .contract import FindingError, validate_findings
from .db import connect
from .ingest import IngestResult, ingest_findings

MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 5_000

router = APIRouter(prefix="/api/v1")


def _unauthorized() -> HTTPException:
    # One response for a missing, malformed, unknown, revoked or wrong-scope key.
    return HTTPException(401, "invalid or missing API key", headers={"WWW-Authenticate": "Bearer"})


def _busy(exc: sqlite3.OperationalError) -> Exception:
    if "locked" in str(exc) or "busy" in str(exc):
        return HTTPException(503, "database is busy, retry", headers={"Retry-After": "5"})
    return exc


def _authorized(token: str) -> bool:
    with closing(connect(config.DB_PATH)) as conn:
        return check_api_key(conn, token, "ingest")


def _store(findings: list[dict[str, Any]]) -> IngestResult:
    with closing(connect(config.DB_PATH)) as conn:
        return ingest_findings(conn, findings, datetime.now(UTC))


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isascii() and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, "request body is over 10 MB")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise HTTPException(413, "request body is over 10 MB")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse(body: bytes) -> tuple[list[dict[str, Any]], list[FindingError]]:
    try:
        findings = json.loads(body)
    except (ValueError, RecursionError) as exc:  # bad JSON, bad UTF-8, nesting too deep
        raise HTTPException(422, f"body is not valid JSON: {exc}") from exc
    if not isinstance(findings, list):
        raise HTTPException(422, "body must be a JSON list of findings")
    if len(findings) > MAX_FINDINGS:
        raise HTTPException(413, f"more than {MAX_FINDINGS} findings in one request")
    return findings, validate_findings(findings)


@router.post("/findings")
async def post_findings(request: Request) -> JSONResponse:
    parts = request.headers.get("authorization", "").split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise _unauthorized()
    try:
        known = await run_in_threadpool(_authorized, parts[1].strip())
    except sqlite3.OperationalError as exc:
        raise _busy(exc) from exc
    if not known:
        raise _unauthorized()

    body = await _read_body(request)
    # Parsing 10 MB and validating 5,000 findings is CPU work: keep it off the event loop.
    findings, errors = await run_in_threadpool(_parse, body)
    if errors:
        return JSONResponse(
            {"errors": [{"index": e.index, "path": e.path, "message": e.message} for e in errors]},
            status_code=422,
        )
    try:
        return JSONResponse(await run_in_threadpool(_store, findings))
    except sqlite3.OperationalError as exc:
        raise _busy(exc) from exc
