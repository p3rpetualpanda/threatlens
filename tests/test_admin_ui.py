from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient

import app.admin_ui as admin_ui
import app.main as main_mod
from app import config
from app.anchor import append_anchor, generate_key, load_key
from app.apikeys import lookup_api_key
from app.audit import record
from app.db import connect, migrate
from app.users import create_user

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
PW = "correct horse battery"
XSS = "<script>alert(1)</script>"
ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"
FORM = {"content-type": "application/x-www-form-urlencoded"}


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", path)
    migrate(path)
    with closing(connect(path)) as conn:
        for name, role in (
            ("viewer", "viewer"),
            ("ann", "analyst"),
            ("lead", "lead"),
            ("admin", "admin"),
        ):
            create_user(conn, f"{name}@example.test", PW, role, NOW)
    yield path


def login(name: str, base: str = "http://localhost") -> tuple[TestClient, str]:
    c = TestClient(main_mod.app, base_url=base, follow_redirects=False)
    body = urlencode({"email": f"{name}@example.test", "password": PW})
    assert c.post("/login", content=body, headers=FORM).status_code == 303
    return c, c.get("/api/v1/me").json()["csrf_token"]


def post(c: TestClient, path: str, csrf: str | None, **fields: str) -> httpx.Response:
    data = {} if csrf is None else {"csrf": csrf}
    r: httpx.Response = c.post(path, content=urlencode({**data, **fields}), headers=FORM)
    return r


def add_audit(n: int, target: str = "t") -> None:
    with closing(connect(config.DB_PATH)) as conn:
        for i in range(n):
            record(conn, "tester", "test.event", f"{target}{i}", None, NOW)
        conn.commit()


def test_audit_page_is_for_lead_and_admin(db: Path) -> None:
    anon = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    assert anon.get("/audit").status_code == 303
    for name in ("viewer", "ann"):
        assert login(name)[0].get("/audit").status_code == 403
    for name in ("lead", "admin"):
        page = login(name)[0].get("/audit")
        assert page.status_code == 200 and "user.create" in page.text
        assert "chain intact" in page.text


def test_audit_page_shows_the_anchor_state(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c, _ = login("lead")
    assert "No anchor configured" in c.get("/audit").text
    key, anchor = db.parent / "k", db.parent / "a.jsonl"
    generate_key(key)
    monkeypatch.setattr(config, "AUDIT_KEY_FILE", str(key))
    monkeypatch.setattr(config, "AUDIT_ANCHOR", str(anchor))
    assert "anchor check failed" in c.get("/audit").text  # configured, but no anchor file yet
    admin_ui._anchored.clear()
    with closing(connect(config.DB_PATH)) as conn:
        append_anchor(conn, load_key(key), anchor, datetime.now(UTC))
    assert "Anchors match" in c.get("/audit").text


def test_audit_page_reports_a_broken_chain(db: Path) -> None:
    c, _ = login("lead")
    with closing(connect(config.DB_PATH)) as conn:
        _unlock(conn)
        conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 1")
        conn.commit()
    page = c.get("/audit").text
    assert "broken at row 1" in page and "chain intact" not in page


def test_audit_page_escapes_and_pages(db: Path) -> None:
    c, _ = login("lead")
    add_audit(1, XSS)
    page = c.get("/audit").text
    assert XSS not in page and ESCAPED in page
    add_audit(60)
    first = c.get("/audit").text
    assert first.count("<tr>") == 51 and "/audit?before=" in first  # 50 rows plus the header row
    last_id = first.split("/audit?before=")[1].split('"')[0]
    older = c.get(f"/audit?before={last_id}").text
    assert "user.create" in older and "/audit?before=" not in older
    for bad in ("0", "abc", "99999999999999999999"):
        assert c.get(f"/audit?before={bad}").status_code == 422


def test_key_pages_are_admin_only(db: Path) -> None:
    for name in ("viewer", "ann", "lead"):
        c, csrf = login(name)
        assert c.get("/admin/keys").status_code == 403
        assert post(c, "/admin/keys", csrf, name="x").status_code == 403
        assert post(c, "/admin/keys/nope/revoke", csrf).status_code == 403
    assert login("admin")[0].get("/admin/keys").status_code == 200


def test_admin_creates_a_key_that_works_and_is_shown_once(db: Path) -> None:
    c, csrf = login("admin")
    posted = post(c, "/admin/keys", csrf, name=XSS)
    assert (posted.status_code, posted.headers["location"]) == (303, "/admin/keys")
    r = c.get("/admin/keys")
    assert r.status_code == 200 and XSS not in r.text and ESCAPED in r.text
    token = r.text.split('<code class="token">')[1].split("</code>")[0]
    with closing(connect(config.DB_PATH)) as conn:
        assert lookup_api_key(conn, token, "ingest") is not None
        assert token not in str(conn.execute("SELECT * FROM api_keys").fetchall()[0][:])
        assert conn.execute("SELECT 1 FROM audit_log WHERE action = 'api_key.create'").fetchone()
    assert token not in c.get("/admin/keys").text  # a refresh does not show it again
    assert "no-store" in r.headers["cache-control"]


def test_key_name_is_required_and_a_wrong_csrf_creates_nothing(db: Path) -> None:
    c, csrf = login("admin")
    for name in ("", "   ", "x" * 101, "‮evil", "ab"):
        assert post(c, "/admin/keys", csrf, name=name).status_code == 422
    assert post(c, "/admin/keys", "wrong", name="ok").status_code == 403
    assert post(c, "/admin/keys", None, name="ok").status_code == 403
    with closing(connect(config.DB_PATH)) as conn:
        assert conn.execute("SELECT count(*) FROM api_keys").fetchone()[0] == 0


def test_admin_revokes_a_key(db: Path) -> None:
    c, csrf = login("admin")
    post(c, "/admin/keys", csrf, name="lab")
    token = c.get("/admin/keys").text.split('<code class="token">')[1].split("</code>")[0]
    with closing(connect(config.DB_PATH)) as conn:
        key_id = conn.execute("SELECT id FROM api_keys").fetchone()[0]
    assert post(c, f"/admin/keys/{key_id}/revoke", "wrong").status_code == 403
    r = post(c, f"/admin/keys/{key_id}/revoke", csrf)
    assert (r.status_code, r.headers["location"]) == (303, "/admin/keys")
    with closing(connect(config.DB_PATH)) as conn:
        assert lookup_api_key(conn, token, "ingest") is None
        assert conn.execute("SELECT 1 FROM audit_log WHERE action = 'api_key.revoke'").fetchone()
    assert "revoked" in c.get("/admin/keys").text
    gone = post(c, "/admin/keys/nope/revoke", csrf)
    assert gone.status_code == 404 and "text/html" in gone.headers["content-type"]


def test_refreshing_the_create_post_page_shows_no_token_and_makes_no_second_key(db: Path) -> None:
    c, csrf = login("admin")
    r = post(c, "/admin/keys", csrf, name="lab")
    assert r.status_code == 303 and "token" not in r.headers["location"]
    assert '<code class="token">' in c.get(r.headers["location"]).text
    assert '<code class="token">' not in c.get("/admin/keys").text
    with closing(connect(config.DB_PATH)) as conn:
        assert conn.execute("SELECT count(*) FROM api_keys").fetchone()[0] == 1


def _unlock(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TRIGGER IF EXISTS audit_no_update")


def _edit_row(row_id: int) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        _unlock(conn)
        conn.execute("UPDATE audit_log SET actor = 'x' WHERE id = ?", [row_id])
        conn.commit()


def test_audit_check_sees_a_middle_edit_at_once_when_the_triggers_are_gone(db: Path) -> None:
    c, _ = login("lead")
    assert "chain intact" in c.get("/audit").text
    _edit_row(1)  # the file was rewritten with the append-only triggers dropped
    assert "broken at row 1" in c.get("/audit").text


def test_an_old_row_edit_shows_after_the_full_pass_interval(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admin_ui, "append_only", lambda conn: True)
    c, _ = login("lead")
    assert "chain intact" in c.get("/audit").text
    _edit_row(1)
    assert "chain intact" in c.get("/audit").text  # between full passes
    monkeypatch.setattr(admin_ui, "_FULL_EVERY", 0)
    assert "broken at row 1" in c.get("/audit").text


def test_between_full_passes_new_rows_and_the_checkpoint_row_are_still_checked(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admin_ui, "append_only", lambda conn: True)
    c, _ = login("lead")
    assert "chain intact" in c.get("/audit").text  # full pass; checkpoint at the newest row
    checkpoint = admin_ui._checked[str(config.DB_PATH)][0][0]  # type: ignore[index]
    add_audit(3)
    _edit_row(checkpoint + 2)
    assert "broken at row" in c.get("/audit").text  # a new row, found without a full pass
    _edit_row(checkpoint)
    assert "broken at row" in c.get("/audit").text  # the checkpoint row itself


def test_a_clean_view_moves_the_checkpoint_to_the_newest_row(db: Path) -> None:
    c, _ = login("lead")
    c.get("/audit")
    add_audit(2)
    c.get("/audit")
    with closing(connect(config.DB_PATH)) as conn:
        newest = conn.execute("SELECT max(id) FROM audit_log").fetchone()[0]
    assert admin_ui._checked[str(config.DB_PATH)][0][0] == newest  # type: ignore[index]


def test_the_token_cookie_is_secure_off_localhost(db: Path) -> None:
    c, csrf = login("admin", "https://lens.example.test")
    assert "secure" in post(c, "/admin/keys", csrf, name="lab").headers["set-cookie"].lower()
    c, csrf = login("admin")
    assert "secure" not in post(c, "/admin/keys", csrf, name="lab2").headers["set-cookie"].lower()


def test_leads_do_not_see_login_rows_but_admins_do(db: Path) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        record(
            conn,
            "anonymous",
            "login.locked",
            None,
            {"email": "x@example.test", "ip": "198.51.100.7"},
            NOW,
        )
        record(conn, "tester", "test.event", "t", {"keep": "visible"}, NOW)
        conn.commit()
    lead, _ = login("lead")
    seen = lead.get("/audit").text
    assert "198.51.100.7" not in seen and "login.locked" not in seen and "visible" in seen
    assert "login.success" not in seen
    admin, _ = login("admin")
    assert "198.51.100.7" in admin.get("/audit").text


def test_a_refusal_page_is_not_titled_not_found(db: Path) -> None:
    c, _ = login("lead")
    r = c.get("/admin/keys")
    assert r.status_code == 403
    assert "<title>Error - ThreatLens</title>" in r.text


def _uid(email: str) -> str:
    with closing(connect(config.DB_PATH)) as conn:
        return str(conn.execute("SELECT id FROM users WHERE email = ?", [email]).fetchone()[0])


def test_users_page_is_admin_only_and_escapes(db: Path) -> None:
    for name in ("viewer", "ann", "lead"):
        assert login(name)[0].get("/admin/users").status_code == 403
    with closing(connect(config.DB_PATH)) as conn:
        create_user(conn, f"{XSS}@example.test", PW, "viewer", NOW)
    page = login("admin")[0].get("/admin/users").text
    assert ESCAPED in page and "<script>alert" not in page


def test_an_admin_creates_a_user_who_can_then_log_in(db: Path) -> None:
    c, csrf = login("admin")
    r = post(c, "/admin/users", csrf, email="New@Example.test", password=PW, role="lead")
    assert r.status_code == 303
    page = c.get("/admin/users").text
    assert "account created" in page and "new@example.test" in page
    assert "account created" not in c.get("/admin/users").text  # shown once
    assert login("new")[1]


def test_bad_new_user_input_is_a_422_that_keeps_the_page(db: Path) -> None:
    c, csrf = login("admin")
    for fields in (
        {"email": "nope", "password": PW, "role": "lead"},
        {"email": "a@example.test", "password": "short", "role": "lead"},
        {"email": "a@example.test", "password": PW, "role": "root"},
        {"email": "ann@example.test", "password": PW, "role": "lead"},  # duplicate
    ):
        r = post(c, "/admin/users", csrf, **fields)
        assert r.status_code == 422 and "Error:" in r.text


def test_changing_a_role_and_disabling_through_the_forms(db: Path) -> None:
    c, csrf = login("admin")
    ann = _uid("ann@example.test")
    assert post(c, f"/admin/users/{ann}/role", csrf, role="lead").status_code == 303
    assert "role changed" in c.get("/admin/users").text
    ann_client, _ = login("ann")
    assert ann_client.get("/audit").status_code == 200  # the new role applies at once
    assert post(c, f"/admin/users/{ann}/disable", csrf).status_code == 303
    assert ann_client.get("/audit").status_code == 303  # the session ended
    assert (
        TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
        .post(
            "/login",
            content=urlencode({"email": "ann@example.test", "password": PW}),
            headers=FORM,
        )
        .status_code
        == 401
    )
    assert post(c, f"/admin/users/{ann}/enable", csrf).status_code == 303
    assert login("ann")[1]


def test_account_rules_show_as_error_pages(db: Path) -> None:
    c, csrf = login("admin")
    me = _uid("admin@example.test")
    assert post(c, f"/admin/users/{me}/role", csrf, role="viewer").status_code == 403
    assert post(c, f"/admin/users/{me}/disable", csrf).status_code == 403
    assert post(c, "/admin/users/nope/disable", csrf).status_code == 404
    assert (
        post(c, f"/admin/users/{_uid('ann@example.test')}/role", csrf, role="x").status_code == 422
    )


def test_account_posts_need_csrf_and_an_admin(db: Path) -> None:
    ann = _uid("ann@example.test")
    c, _ = login("admin")
    assert post(c, f"/admin/users/{ann}/disable", None).status_code == 403
    lead, lead_csrf = login("lead")
    assert post(lead, f"/admin/users/{ann}/disable", lead_csrf).status_code == 403
    assert (
        post(lead, "/admin/users", lead_csrf, email="x@example.test", password=PW).status_code
        == 403
    )
