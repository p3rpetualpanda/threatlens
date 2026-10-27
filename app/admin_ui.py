"""Audit log (lead+) and API-key pages (admin) as server-rendered forms (spec 6.7 items 6, 7).

Same gate as app.ui_actions: session, body cap, Origin, role, hidden `csrf` field. A new key's
token is rendered once, on the response to the create post; the global no-store header keeps it
out of caches and it is never written to the audit log.
"""

from __future__ import annotations

import sqlite3
import time
import unicodedata
from contextlib import closing
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from . import config, flash
from .apikeys import create_api_key, revoke_api_key
from .audit import verify
from .db import connect
from .sessions import Session
from .ui import _page, _viewer
from .ui_actions import _gate
from .users import ROLES

router = APIRouter()
_PAGE = 50
_MAX_NAME = 100
_NEWKEY = "threatlens_newkey"  # carries a new token across the redirect, for 60 s
_VERIFY_TTL = 30.0
_verified_at: tuple[float, str, int, int | None] | None = None  # time, db, last id, result


def _verified(conn: sqlite3.Connection) -> int | None:
    """verify() walks the whole chain, so reuse a result for 30 s while the log is unchanged.

    shortcut: an edit made in the middle of the chain shows up within 30 s, not at once, and a
    lead reloading /audit can no longer hold the database busy; move to incremental checking
    once the log reaches hundreds of thousands of rows.
    """
    global _verified_at
    last = conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log").fetchone()[0]
    db = str(config.DB_PATH)
    now = time.monotonic()
    if _verified_at and _verified_at[1:3] == (db, last) and now - _verified_at[0] < _VERIFY_TTL:
        return _verified_at[3]
    result = verify(conn)
    _verified_at = (now, db, last, result)
    return result


def _need(request: Request, minimum: str) -> Session | Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if ROLES.index(session.user.role) < ROLES.index(minimum):
        return _page(request, "error.html", session, 403, message="your role cannot do this")
    return session


@router.get("/audit", response_class=HTMLResponse, include_in_schema=False)
def audit_log(
    request: Request, before: Annotated[int | None, Query(ge=1, le=2**63 - 1)] = None
) -> Response:
    session = _need(request, "lead")
    if isinstance(session, Response):
        return session
    with closing(connect(config.DB_PATH)) as conn:
        broken = _verified(conn)
        rows = conn.execute(
            "SELECT id, at, actor, action, target, detail FROM audit_log "
            "WHERE (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2",
            [before, _PAGE + 1],
        ).fetchall()
    more = len(rows) > _PAGE
    rows = rows[:_PAGE]
    return _page(
        request,
        "audit.html",
        session,
        rows=rows,
        broken=broken,
        next_before=rows[-1]["id"] if more else None,
    )


def _keys(
    request: Request,
    session: Session,
    code: int = 200,
    created: tuple[str, str] | None = None,
    error: str | None = None,
) -> Response:
    name, token = created if created else (None, None)
    with closing(connect(config.DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT id, name, scope, created_at, revoked_at FROM api_keys "
            "ORDER BY created_at DESC, id LIMIT 500"
        ).fetchall()
    return _page(
        request, "keys.html", session, code, rows=rows, token=token, key_name=name, error=error
    )


@router.get("/admin/keys", response_class=HTMLResponse, include_in_schema=False)
def key_list(request: Request) -> Response:
    session = _need(request, "admin")
    if isinstance(session, Response):
        return session
    name = flash.pop(session.csrf_token, "key")
    token = request.cookies.get(_NEWKEY)
    shown = _keys(request, session, created=(name[0], token) if name and token else None)
    shown.delete_cookie(_NEWKEY, path="/admin/keys")  # one view only
    return shown


def _create(actor: str, name: str) -> str:
    with closing(connect(config.DB_PATH)) as conn:
        return create_api_key(conn, name, datetime.now(UTC), actor)


def _revoke(actor: str, key_id: str) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        revoke_api_key(conn, key_id, datetime.now(UTC), actor)


@router.post("/admin/keys", include_in_schema=False)
async def key_create(request: Request) -> Response:
    gate = await _gate(request, "admin")
    if isinstance(gate, Response):
        return gate
    session, form = gate
    name = form.get("name", [""])[0].strip()
    # Cc/Cf (control, bidi override) could reorder or mask the name in tables and the audit log
    if (
        not name
        or len(name) > _MAX_NAME
        or any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name)
    ):
        msg = f"name must be 1 to {_MAX_NAME} characters"
        return await run_in_threadpool(_keys, request, session, 422, None, msg)
    token = await run_in_threadpool(_create, session.user.email, name)
    # Redirect so a refresh cannot repeat the POST. The token travels in a short HttpOnly cookie,
    # not the database; only the key name waits in the flash table.
    await run_in_threadpool(flash.put, session.csrf_token, "key", [name])
    out = RedirectResponse("/admin/keys", status_code=303)
    out.set_cookie(
        _NEWKEY,
        token,
        max_age=60,
        path="/admin/keys",
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )
    return out


@router.post("/admin/keys/{key_id}/revoke", include_in_schema=False)
async def key_revoke(
    request: Request, key_id: Annotated[str, PathParam(max_length=64)]
) -> Response:
    gate = await _gate(request, "admin")
    if isinstance(gate, Response):
        return gate
    session, _ = gate
    try:
        await run_in_threadpool(_revoke, session.user.email, key_id)
    except KeyError:
        return _page(request, "error.html", session, 404, message="no such key")
    return RedirectResponse("/admin/keys", status_code=303)
