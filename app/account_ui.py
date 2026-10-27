"""`/account`: a signed-in user changes their own password (any role)."""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from . import config, flash
from .accounts import AccountError, change_own_password
from .auth import COOKIE
from .db import connect
from .sessions import Session
from .ui import _page, _viewer
from .ui_actions import _gate

router = APIRouter()


def _form(
    request: Request, session: Session, code: int = 200, error: str | None = None
) -> Response:
    done = flash.pop(session.csrf_token, "account")
    return _page(request, "account.html", session, code, error=error, done=done)


def _change(session: Session, token: str, current: str, new: str) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        change_own_password(conn, session.user, current, new, token, datetime.now(UTC))


@router.get("/account", response_class=HTMLResponse, include_in_schema=False)
def account(request: Request) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    return _form(request, session)


@router.post("/account/password", include_in_schema=False)
async def account_password(request: Request) -> Response:
    gate = await _gate(request, "viewer")
    if isinstance(gate, Response):
        return gate
    session, form = gate
    current, new, again = (form.get(k, [""])[0] for k in ("current", "new", "again"))
    if new != again:
        return await run_in_threadpool(_form, request, session, 422, "the new passwords differ")
    try:
        await run_in_threadpool(_change, session, request.cookies.get(COOKIE, ""), current, new)
    except AccountError as exc:
        return await run_in_threadpool(_form, request, session, exc.status, exc.message)
    await run_in_threadpool(flash.put, session.csrf_token, "account", "password changed")
    return RedirectResponse("/account", status_code=303)
