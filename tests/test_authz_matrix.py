"""Every route x every kind of caller, against the expected status code (spec §6.9).

The completeness test walks `app.routes`: a new route without a row here fails the build, so
nobody can add an endpoint without deciding who may call it.
"""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import config
from app.apikeys import create_api_key
from app.db import connect, migrate
from app.users import ROLES, create_user

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
PW = "correct horse battery"
PRINCIPALS = ("anonymous", *ROLES, "ingest_key")


def _all(status: int) -> dict[str, int]:
    return dict.fromkeys(PRINCIPALS, status)


def _session_route(status: int) -> dict[str, int]:
    """Any logged-in role gets `status`; anonymous and a bearer key are refused."""
    return {**dict.fromkeys(ROLES, status), "anonymous": 401, "ingest_key": 401}


# (method, path) -> (expected status per principal, request kwargs)
MATRIX: dict[tuple[str, str], tuple[dict[str, int], dict[str, Any]]] = {
    ("GET", "/health"): (_all(200), {}),
    ("GET", "/docs"): (_all(200), {}),
    ("GET", "/redoc"): (_all(200), {}),
    ("GET", "/openapi.json"): (_all(200), {}),
    ("GET", "/docs/oauth2-redirect"): (_all(200), {}),
    # An empty list is a valid, harmless ingest; only a bearer key may send it.
    ("POST", "/api/v1/findings"): (
        {**dict.fromkeys(ROLES, 401), "anonymous": 401, "ingest_key": 200},
        {"json": []},
    ),
    # Public by nature; an empty body is rejected before any password is checked.
    ("POST", "/api/v1/login"): (_all(422), {"json": {}}),
    ("POST", "/api/v1/logout"): (_session_route(204), {}),
    ("GET", "/api/v1/me"): (_session_route(200), {}),
    ("GET", "/api/v1/incidents"): (_session_route(200), {}),
    # the literal "{incident_id}" is an unknown id: a logged-in caller gets 404, not 401/403
    ("GET", "/api/v1/incidents/{incident_id}"): (_session_route(404), {}),
}
_INC = "/api/v1/incidents/{incident_id}"


def _acting(minimum: str, body: dict[str, Any]) -> tuple[dict[str, int], dict[str, Any]]:
    """Roles below `minimum` get 403; the rest reach the handler and find no such incident."""
    need = ROLES.index(minimum)
    allowed = {r: 403 if ROLES.index(r) < need else 404 for r in ROLES}
    return {**allowed, "anonymous": 401, "ingest_key": 401}, {"json": body}


MATRIX |= {
    ("POST", f"{_INC}/take"): _acting("analyst", {}),
    ("POST", f"{_INC}/assign"): _acting("lead", {"owner": None}),
    ("POST", f"{_INC}/status"): _acting("analyst", {"status": "new"}),
    ("POST", f"{_INC}/disposition"): _acting("analyst", {"disposition": None}),
    ("POST", f"{_INC}/comments"): _acting("analyst", {"body": "x"}),
    ("POST", f"{_INC}/merge"): _acting("lead", {"into": "other"}),
    ("POST", f"{_INC}/split"): _acting("lead", {"alerts": ["a"]}),
}
_PAGE = {**dict.fromkeys(ROLES, 200), "anonymous": 303, "ingest_key": 303}  # 303 goes to /login
MATRIX |= {
    ("GET", "/login"): (_all(200), {}),
    ("POST", "/login"): (_all(401), {"content": "email=&password="}),
    ("GET", "/static/app.css"): (_all(200), {}),
    ("GET", "/"): (_PAGE, {}),
    ("GET", "/incidents/{incident_id}"): ({**_PAGE, **dict.fromkeys(ROLES, 404)}, {}),
    ("GET", "/alerts/{uid:path}"): ({**_PAGE, **dict.fromkeys(ROLES, 404)}, {}),
}
# Form posts carry a hidden csrf field, not the header, so every logged-in role is refused here
# (403 for csrf, or for role); tests/test_ui_actions.py covers what happens with a valid field.
_FORM = {**dict.fromkeys(ROLES, 403), "anonymous": 303, "ingest_key": 303}
for _a in ("take", "assign", "status", "disposition", "comment", "merge", "split"):
    MATRIX[("POST", f"/incidents/{{incident_id}}/{_a}")] = (_FORM, {})
MATRIX[("POST", "/logout")] = (_FORM, {})
_AUDIT_ROLES = {"viewer": 403, "analyst": 403, "lead": 200, "admin": 200}
MATRIX[("GET", "/audit")] = ({**_AUDIT_ROLES, "anonymous": 303, "ingest_key": 303}, {})
_KEYS = {"viewer": 403, "analyst": 403, "lead": 403, "admin": 200}
MATRIX[("GET", "/admin/keys")] = ({**_KEYS, "anonymous": 303, "ingest_key": 303}, {})
MATRIX[("POST", "/admin/keys")] = (_FORM, {})
MATRIX[("POST", "/admin/keys/{key_id}/revoke")] = (_FORM, {})
CASES = [(key, who) for key in MATRIX for who in PRINCIPALS]


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as conn:
        for role in ROLES:
            create_user(conn, f"{role}@example.test", PW, role, NOW)
        return create_api_key(conn, "lab", NOW)


def _call(who: str, method: str, path: str, kwargs: dict[str, Any], key: str, csrf: bool = True):  # type: ignore[no-untyped-def]
    client = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    headers: dict[str, str] = {}
    if who in ROLES:
        resp = client.post("/api/v1/login", json={"email": f"{who}@example.test", "password": PW})
        assert resp.status_code == 200
        if csrf:
            headers["X-CSRF-Token"] = resp.json()["csrf_token"]
    elif who == "ingest_key":
        headers["Authorization"] = f"Bearer {key}"
    return client.request(method, path, headers=headers, **kwargs)


def _walk(routes: list[Any], prefix: str = "") -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for route in routes:
        if hasattr(route, "original_router"):  # an include_router() wrapper
            found |= _walk(route.original_router.routes, prefix + route.include_context.prefix)
        elif hasattr(route, "methods"):
            found |= {
                (m, prefix + route.path) for m in route.methods if m not in {"HEAD", "OPTIONS"}
            }
        else:  # a Mount or anything else we cannot list: make the test say so
            raise AssertionError(f"matrix cannot enumerate {type(route).__name__}")
    return found


def test_every_route_has_a_matrix_row() -> None:
    routes = _walk(main_mod.app.routes)
    assert routes == set(MATRIX), (
        f"routes without a row: {sorted(routes - set(MATRIX))}; "
        f"rows without a route: {sorted(set(MATRIX) - routes)}"
    )


@pytest.mark.parametrize(("route", "who"), CASES, ids=[f"{m} {p} {w}" for (m, p), w in CASES])
def test_matrix(setup: str, route: tuple[str, str], who: str) -> None:
    method, path = route
    expected, kwargs = MATRIX[route]
    resp = _call(who, method, path, kwargs, setup)
    assert resp.status_code == expected[who], resp.text[:200]


@pytest.mark.parametrize("role", ROLES)
def test_session_routes_that_change_state_need_the_csrf_header(setup: str, role: str) -> None:
    for (method, path), (expected, kwargs) in MATRIX.items():
        if method != "POST" or expected[role] == 401 or path == "/api/v1/login":
            continue
        resp = _call(role, method, path, kwargs, setup, csrf=False)
        assert resp.status_code == 403, (path, resp.status_code)
