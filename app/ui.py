"""Server-rendered analyst pages (spec 6.7): login, incident queue, incident detail. Read-only.

Jinja2 autoescape is on for every template and nothing here marks a value safe. Pages carry no
inline script or style, so the CSP in app.main (default-src 'self') stays as it is.
"""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BeforeValidator, ValidationError
from starlette.concurrency import run_in_threadpool

from . import config, flash, workflow
from .auth import LoginBody, login, require_role
from .db import connect
from .enrich import ip_class
from .incidents_api import get_incident
from .risk import label, load_risk_config
from .sessions import Session
from .users import ROLES

_HERE = Path(__file__).resolve().parent
_templates = Jinja2Templates(directory=str(_HERE / "templates"))
_MAX_FORM = 4096
router = APIRouter()


def _viewer(request: Request) -> Session | None:
    try:
        return require_role("viewer")(request)
    except HTTPException:
        return None


def _page(
    request: Request, name: str, session: Session | None, code: int = 200, **ctx: Any
) -> Response:
    user = session.user if session else None
    csrf = session.csrf_token if session else None
    return _templates.TemplateResponse(
        request, name, {"user": user, "csrf": csrf, **ctx}, status_code=code
    )


@router.get("/static/app.css", include_in_schema=False)
def css() -> FileResponse:
    return FileResponse(_HERE / "static" / "app.css", media_type="text/css")


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_form(request: Request) -> Response:
    return _page(request, "login.html", None)


def cross_site(request: Request) -> bool:
    """True for a form post from another origin (a missing Origin header is allowed)."""
    origin = request.headers.get("origin")
    return bool(origin) and urlsplit(origin).netloc != request.headers.get("host")


async def read_form(request: Request, limit: int = _MAX_FORM) -> dict[str, list[str]] | None:
    """Parse a urlencoded body; None when it is over `limit` bytes."""
    raw = bytearray()
    # the middleware cap trusts Content-Length; a chunked body skips it
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > limit:
            return None
    return parse_qs(raw.decode("utf-8", "replace"))


@router.post("/login", include_in_schema=False)
async def login_submit(request: Request) -> Response:
    if cross_site(request):
        # a cross-site form post could otherwise sign the victim into the attacker's account
        return _page(request, "login.html", None, 403, error="cross-site login refused")
    form = await read_form(request)
    if form is None:
        return _page(request, "login.html", None, 413, error="request too large")
    try:
        body = LoginBody(email=form.get("email", [""])[0], password=form.get("password", [""])[0])
        result = await run_in_threadpool(login, body, request)  # argon2 must not block the loop
    except (ValidationError, HTTPException) as exc:
        if isinstance(exc, HTTPException):
            page = _page(request, "login.html", None, exc.status_code, error=exc.detail)
            page.headers.update(exc.headers or {})
            return page
        return _page(request, "login.html", None, 401, error="invalid email or password")
    out = RedirectResponse("/", status_code=303)
    out.headers["set-cookie"] = result.headers["set-cookie"]
    return out


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def queue(
    request: Request,
    status: Annotated[
        Literal["new", "in_progress", "resolved"] | None, BeforeValidator(lambda v: v or None)
    ] = None,  # the form's "any" option sends status=
    environment: Annotated[str | None, Query(max_length=200)] = None,
    owner: Annotated[str | None, Query(max_length=254)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    cfg = load_risk_config()
    with closing(connect(config.DB_PATH)) as conn:
        found = conn.execute(
            "SELECT i.id, i.environment, i.title, i.status, i.risk_score, i.last_seen, "
            "u.email AS owner_email, "
            "(SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.id) AS alert_count "
            "FROM incidents i LEFT JOIN users u ON u.id = i.owner WHERE i.merged_into IS NULL "
            "AND (?1 IS NULL OR i.status = ?1) AND (?2 IS NULL OR i.environment = ?2) "
            "AND (?3 IS NULL OR lower(u.email) = lower(?3)) "
            "ORDER BY i.risk_score IS NULL, i.risk_score DESC, i.last_seen DESC, i.id LIMIT ?4",
            [status or None, environment or None, owner or None, limit],
        ).fetchall()
    rows = [
        {**dict(r), "label": None if r["risk_score"] is None else label(r["risk_score"], cfg)}
        for r in found
    ]
    ctx: dict[str, Any] = {
        "rows": rows,
        "status": status,
        "environment": environment,
        "owner": owner,
    }
    return _page(request, "queue.html", session, **ctx)


def _entities(conn: Any, incident_id: str, environment: str) -> list[dict[str, str]]:
    found = conn.execute(
        "SELECT DISTINCT e.kind, e.value FROM alert_entities e "
        "JOIN incident_alerts ia ON ia.alert_id = e.alert_id WHERE ia.incident_id = ? "
        "ORDER BY e.kind, e.value",
        [incident_id],
    ).fetchall()
    out = []
    for r in found:
        ctx = ""
        if r["kind"] in ("src_ip", "dst_ip"):
            ctx = ip_class(r["value"])
        elif r["kind"] == "host":
            a = conn.execute(
                "SELECT criticality FROM assets WHERE environment = ? AND host = ?",
                [environment, r["value"].lower()],
            ).fetchone()
            ctx = f"criticality {a['criticality']}" if a else ""
        elif r["kind"] == "user":
            p = conn.execute(
                "SELECT privileged FROM identities WHERE environment = ? AND user = ?",
                [environment, r["value"].lower()],
            ).fetchone()
            ctx = "privileged" if p and p["privileged"] else ""
        out.append({"kind": r["kind"], "value": r["value"], "context": ctx})
    return out


# one-shot flash (app.flash) after a good action; only these fixed texts are ever shown
DONE = {
    "take": "Incident taken.",
    "assign": "Owner updated.",
    "status": "Status updated.",
    "disposition": "Disposition updated.",
    "step": "Playbook step updated.",
    "comment": "Comment added.",
    "merge": "Incidents merged.",
    "split": "Incident split.",
}


def render_incident(
    request: Request,
    session: Session,
    incident_id: str,
    code: int = 200,
    error: str | None = None,
) -> Response:
    """The incident page; `error` and `code` carry a refused action back to the same page."""
    try:
        inc = get_incident(incident_id)
    except HTTPException as exc:
        return _page(request, "error.html", session, exc.status_code, message=exc.detail)
    if inc["merged_into"]:  # the queue hides merged incidents; follow the merge
        if error:  # a stale tab acted on the merged one: show the message on the survivor
            return render_incident(request, session, inc["merged_into"], code, error)
        return RedirectResponse(f"/incidents/{quote(inc['merged_into'])}", status_code=303)
    with closing(connect(config.DB_PATH)) as conn:
        timeline = conn.execute(
            "SELECT a.finding_info_uid AS uid, a.time, a.rule, a.severity, a.technique, "
            "ia.pinned FROM incident_alerts ia "
            "JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = ? "
            "ORDER BY a.time, a.finding_info_uid",
            [incident_id],
        ).fetchall()
        ents = _entities(conn, incident_id, inc["environment"])
        steps = workflow.incident_steps(conn, incident_id)
    rank = ROLES.index(session.user.role)  # buttons are a convenience; app.workflow enforces
    live = inc["status"] != "resolved"  # a resolved incident only allows a lead to reopen it
    work = rank >= 1 and (inc["owner"] == session.user.id or rank >= 2)
    opts = []
    if live and work:
        opts.append("resolved")
        if inc["owner"] and inc["status"] != "in_progress":
            opts.append("in_progress")
    elif not live and rank >= 2:
        opts.append("in_progress")
    can = {
        "take": live and rank >= 1 and not inc["owner"],
        "work": live and work,
        "comment": rank >= 1,
        "lead": live and rank >= 2,
        "status_opts": opts,
    }
    return _page(
        request,
        "incident.html",
        session,
        code,
        inc=inc,
        entities=ents,
        timeline=timeline,
        steps=steps,
        can=can,
        error=error,
        notice=DONE.get(str(flash.pop(session.csrf_token, "done"))),
    )


@router.get("/incidents/{incident_id}", response_class=HTMLResponse, include_in_schema=False)
def incident(
    request: Request,
    incident_id: Annotated[str, PathParam(max_length=64)],
) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    return render_incident(request, session, incident_id)


@router.get("/alerts/{uid:path}", response_class=HTMLResponse, include_in_schema=False)
def alert(request: Request, uid: str) -> Response:  # :path, so a uid containing "/" works
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    with closing(connect(config.DB_PATH)) as conn:
        found = conn.execute(
            "SELECT rule, severity, time, environment, raw_json FROM alerts "
            "WHERE finding_info_uid = ?",
            [uid],
        ).fetchall()
    if len(found) != 1:  # none, or the same uid in two environments: do not guess
        return _page(request, "error.html", session, 404, message="no such alert")
    row = found[0]
    raw = json.dumps(json.loads(row["raw_json"]), indent=2, sort_keys=True)
    return _page(request, "alert.html", session, uid=uid, alert=dict(row), raw=raw)
