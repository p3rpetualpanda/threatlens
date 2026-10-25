"""Analyst login, logout and the role/CSRF gate for cookie-authenticated routes.

Ingest uses bearer API keys (app.api) and never touches this module. Everything else that a
person uses goes through `require_role`, which checks, in this order: a live session (401),
a role at or above the minimum (403), and for non-safe methods the CSRF header (403).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config
from .audit import record
from .db import connect
from .lockout import WINDOW, clear, is_locked, keys_for, record_failure
from .sessions import IDLE_TIMEOUT, Session, create_session, delete_session, get_session
from .users import ROLES, authenticate

COOKIE = "tl_session"
CSRF_HEADER = "x-csrf-token"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

router = APIRouter(prefix="/api/v1")


class LoginBody(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=1024)


def require_role(minimum: str) -> Callable[[Request], Session]:
    if minimum not in ROLES:
        raise ValueError(f"unknown role {minimum!r}")
    needed = ROLES.index(minimum)

    def dependency(request: Request) -> Session:
        token = request.cookies.get(COOKIE)
        session = None
        if token:
            with closing(connect(config.DB_PATH)) as conn:
                session = get_session(conn, token, datetime.now(UTC))
        if session is None:
            raise HTTPException(401, "login required")
        if ROLES.index(session.user.role) < needed:
            raise HTTPException(403, "your role cannot do this")
        if request.method not in _SAFE_METHODS:
            sent = request.headers.get(CSRF_HEADER, "").encode()
            if not secrets.compare_digest(sent, session.csrf_token.encode()):
                raise HTTPException(403, "missing or wrong CSRF token")
        return session

    return dependency


def _session_json(session: Session) -> dict[str, object]:
    user = session.user
    return {
        "user": {"id": user.id, "email": user.email, "role": user.role},
        "csrf_token": session.csrf_token,
    }


@router.post("/login")
def login(body: LoginBody, request: Request) -> JSONResponse:
    now = datetime.now(UTC)
    ip = request.client.host if request.client else "unknown"
    keys = keys_for(body.email, ip)
    with closing(connect(config.DB_PATH)) as conn:
        if is_locked(conn, keys, now):
            raise HTTPException(
                429,
                "too many failed logins, try again later",
                headers={"Retry-After": str(int(WINDOW.total_seconds()))},
            )
        user = authenticate(conn, body.email, body.password)
        if user is None:
            record_failure(conn, keys, now)
            if is_locked(conn, keys, now):  # audit the lock once, not every refused attempt
                email = body.email.strip().lower()
                record(conn, "anonymous", "login.locked", None, {"email": email, "ip": ip}, now)
                conn.commit()
            raise HTTPException(401, "invalid email or password")
        clear(conn, keys[0])  # the username only: a good login must not reset the IP's count
        token, csrf = create_session(conn, user.id, now)  # always new: no session fixation
        record(conn, user.email, "login.success", user.id, {"ip": ip}, now)
        conn.commit()
    response = JSONResponse(_session_json(Session(user, csrf)))
    response.set_cookie(
        COOKIE,
        token,
        max_age=int(IDLE_TIMEOUT.total_seconds()),
        httponly=True,
        samesite="strict",
        secure=request.url.hostname not in _LOCAL_HOSTS,
        path="/",
    )
    return response


@router.post("/logout", status_code=204)
def logout(request: Request, session: Session = Depends(require_role("viewer"))) -> Response:  # noqa: B008
    with closing(connect(config.DB_PATH)) as conn:
        delete_session(conn, request.cookies[COOKIE])
        record(conn, session.user.email, "logout", session.user.id, None, datetime.now(UTC))
        conn.commit()
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/me")
def me(session: Session = Depends(require_role("viewer"))) -> dict[str, object]:  # noqa: B008
    return _session_json(session)
