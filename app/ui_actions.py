"""Analyst actions as plain HTML form posts (spec 6.7); the rules live in app.workflow.

A form cannot set the X-CSRF-Token header the JSON routes need, so these routes read the same
per-session token from a hidden `csrf` field instead. Every refusal re-renders a page; no user
text goes through the URL.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi import Path as PathParam
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from . import config, flash, workflow
from .auth import COOKIE, logout
from .db import connect
from .sessions import Session, get_session
from .ui import _page, cross_site, read_form, render_incident
from .users import ROLES, User

router = APIRouter()
IncidentId = Annotated[str, PathParam(max_length=64)]
Form = dict[str, list[str]]
_SMALL, _BIG = 4096, 32768  # a split posts one uid per ticked alert; a comment can hold non-ASCII
_BIG_FORMS = {"comment", "split"}
Call = Callable[[Any, User, str, Form, datetime], object]


def _one(form: Form, key: str) -> str:
    return form.get(key, [""])[0]


# action -> (minimum role, service call); the service still checks ownership and the rest
ACTIONS: dict[str, tuple[str, Call]] = {
    "take": ("analyst", lambda c, u, i, f, n: workflow.take(c, u, i, n)),
    "assign": (
        "lead",
        lambda c, u, i, f, n: workflow.assign(c, u, i, _one(f, "owner").strip() or None, n),
    ),
    "status": ("analyst", lambda c, u, i, f, n: workflow.set_status(c, u, i, _one(f, "status"), n)),
    "disposition": (
        "analyst",
        lambda c, u, i, f, n: workflow.set_disposition(c, u, i, _one(f, "disposition") or None, n),
    ),
    "step": (
        "analyst",
        lambda c, u, i, f, n: workflow.set_step(
            c, u, i, _one(f, "step"), _one(f, "done") == "1", n
        ),
    ),
    "comment": ("analyst", lambda c, u, i, f, n: workflow.add_comment(c, u, i, _one(f, "body"), n)),
    "merge": ("lead", lambda c, u, i, f, n: workflow.merge(c, u, i, _one(f, "into").strip(), n)),
    "split": ("lead", lambda c, u, i, f, n: workflow.split(c, u, i, f.get("alert", []), n)),
}


def _session(request: Request) -> Session | None:
    """The session behind the cookie; unlike require_role it does not want the CSRF header."""
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    with closing(connect(config.DB_PATH)) as conn:
        return get_session(conn, token, datetime.now(UTC))


def _csrf_ok(session: Session, form: Form) -> bool:
    sent = _one(form, "csrf").encode()
    # an empty stored token (pre-migration row) must never match an empty field
    return bool(sent) and secrets.compare_digest(sent, session.csrf_token.encode())


def _write(user: User, iid: str, call: Call, form: Form) -> None:
    """One write transaction around a service call."""
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            call(conn, user, iid, form, datetime.now(UTC))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


async def _gate(
    request: Request, minimum: str, limit: int = _SMALL
) -> tuple[Session, Form] | Response:
    """Everything a state-changing form post must pass before it reaches the database."""
    session = await run_in_threadpool(_session, request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    form = await read_form(request, limit)
    if form is None:
        return _page(request, "error.html", session, 413, message="request too large")
    if cross_site(request):
        return _page(request, "error.html", session, 403, message="cross-site request refused")
    if ROLES.index(session.user.role) < ROLES.index(minimum):
        return _page(request, "error.html", session, 403, message="your role cannot do this")
    if not _csrf_ok(session, form):
        return _page(request, "error.html", session, 403, message="missing or wrong CSRF token")
    return session, form


def _register(name: str, minimum: str, call: Call) -> None:
    limit = _BIG if name in _BIG_FORMS else _SMALL

    async def handler(request: Request, incident_id: IncidentId) -> Response:
        gate = await _gate(request, minimum, limit)
        if isinstance(gate, Response):
            return gate
        session, form = gate
        try:
            await run_in_threadpool(_write, session.user, incident_id, call, form)
        except workflow.WorkflowError as exc:
            return await run_in_threadpool(
                render_incident, request, session, incident_id, exc.status, exc.message
            )
        await run_in_threadpool(flash.put, session.csrf_token, "done", name)
        return RedirectResponse(f"/incidents/{quote(incident_id)}", status_code=303)

    router.add_api_route(
        f"/incidents/{{incident_id}}/{name}", handler, methods=["POST"], include_in_schema=False
    )


for _name, (_minimum, _call) in ACTIONS.items():
    _register(_name, _minimum, _call)


@router.post("/logout", include_in_schema=False)
async def sign_out(request: Request) -> Response:
    gate = await _gate(request, "viewer")
    if isinstance(gate, Response):
        return gate
    done = await run_in_threadpool(logout, request, gate[0])
    out = RedirectResponse("/login", status_code=303)
    out.headers["set-cookie"] = done.headers["set-cookie"]
    return out
