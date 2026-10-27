"""Server-rendered analyst pages (spec 6.7): login, incident queue, incident detail. Read-only.

Jinja2 autoescape is on for every template and nothing here marks a value safe. Pages carry no
inline script or style, so the CSP in app.main (default-src 'self') stays as it is.
"""

from __future__ import annotations

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

from . import config
from .auth import LoginBody, login, require_role
from .db import connect
from .enrich import ip_class
from .incidents_api import get_incident
from .risk import label, load_risk_config
from .sessions import Session

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
    return _templates.TemplateResponse(request, name, {"user": user, **ctx}, status_code=code)


@router.get("/static/app.css", include_in_schema=False)
def css() -> FileResponse:
    return FileResponse(_HERE / "static" / "app.css", media_type="text/css")


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_form(request: Request) -> Response:
    return _page(request, "login.html", None)


@router.post("/login", include_in_schema=False)
async def login_submit(request: Request) -> Response:
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host"):
        # a cross-site form post could otherwise sign the victim into the attacker's account
        return _page(request, "login.html", None, 403, error="cross-site login refused")
    raw = bytearray()
    async for (
        chunk
    ) in request.stream():  # the middleware cap trusts Content-Length; chunked skips it
        raw += chunk
        if len(raw) > _MAX_FORM:
            return _page(request, "login.html", None, 413, error="request too large")
    form = parse_qs(raw.decode("utf-8", "replace"))
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


@router.get("/incidents/{incident_id}", response_class=HTMLResponse, include_in_schema=False)
def incident(request: Request, incident_id: Annotated[str, PathParam(max_length=64)]) -> Response:
    session = _viewer(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    try:
        inc = get_incident(incident_id)
    except HTTPException as exc:
        return _page(request, "error.html", session, exc.status_code, message=exc.detail)
    if inc["merged_into"]:  # the queue hides merged incidents; follow the merge
        return RedirectResponse(f"/incidents/{quote(inc['merged_into'])}", status_code=303)
    with closing(connect(config.DB_PATH)) as conn:
        timeline = conn.execute(
            "SELECT a.time, a.rule, a.severity, a.technique, ia.pinned FROM incident_alerts ia "
            "JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = ? "
            "ORDER BY a.time, a.finding_info_uid",
            [incident_id],
        ).fetchall()
        ents = _entities(conn, incident_id, inc["environment"])
    return _page(request, "incident.html", session, inc=inc, entities=ents, timeline=timeline)
