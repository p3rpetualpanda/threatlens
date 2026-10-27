from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient
from incident_helpers import NOW, add, run

import app.main as main_mod
from app import config
from app.db import connect, migrate
from app.users import create_user

PW = "correct horse battery"

XSS = "<script>alert(1)</script>"

ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"

FORM = {"content-type": "application/x-www-form-urlencoded"}


class Ctx:
    def __init__(self, a: str, b: str) -> None:

        self.a, self.b = a, b  # two incidents in environment "e"


@pytest.fixture
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Ctx]:

    db = tmp_path / "t.db"

    monkeypatch.setattr(config, "DB_PATH", db)

    migrate(db)

    with closing(connect(db)) as conn:
        for name, role in (
            ("viewer", "viewer"),
            ("ann", "analyst"),
            ("bob", "analyst"),
            ("lead", "lead"),
        ):
            create_user(conn, f"{name}@example.test", PW, role, NOW)

        add(conn, "a1", 0, host="h1")

        add(conn, "a2", 5, host="h1", rule="R02")

        add(conn, "b1", 600, host="h2", rule=XSS)

        conn.execute("UPDATE alerts SET raw_json = ? WHERE id = 'b1'", [json.dumps({"x": XSS})])

        run(conn)

        ids = [r[0] for r in conn.execute("SELECT id FROM incidents ORDER BY first_seen")]

        yield Ctx(ids[0], ids[1])


def login(name: str) -> tuple[TestClient, str]:

    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)

    r = c.post(
        "/login", content=urlencode({"email": f"{name}@example.test", "password": PW}), headers=FORM
    )

    assert r.status_code == 303, r.text

    return c, c.get("/api/v1/me").json()["csrf_token"]


def act(
    c: TestClient, csrf: str | None, iid: str, action: str, **fields: str | list[str]
) -> httpx.Response:

    data = {} if csrf is None else {"csrf": csrf}

    r: httpx.Response = c.post(
        f"/incidents/{iid}/{action}",
        content=urlencode({**data, **fields}, doseq=True),
        headers=FORM,
    )

    return r


def row(iid: str) -> dict[str, object]:

    with closing(connect(config.DB_PATH)) as conn:
        return dict(conn.execute("SELECT * FROM incidents WHERE id = ?", [iid]).fetchone())


def audited(action: str) -> bool:

    with closing(connect(config.DB_PATH)) as conn:
        return (
            conn.execute("SELECT 1 FROM audit_log WHERE action = ?", [action]).fetchone()
            is not None
        )


def test_analyst_works_an_incident_through_the_forms(ctx: Ctx) -> None:

    c, csrf = login("ann")

    r = act(c, csrf, ctx.a, "take")

    assert (r.status_code, r.headers["location"]) == (303, f"/incidents/{ctx.a}")

    assert row(ctx.a)["status"] == "in_progress" and audited("incident.take")

    assert act(c, csrf, ctx.a, "comment", body="seen it").status_code == 303

    assert "seen it" in c.get(f"/incidents/{ctx.a}").text and audited("incident.comment")

    assert act(c, csrf, ctx.a, "disposition", disposition="true_positive").status_code == 303

    assert row(ctx.a)["disposition"] == "true_positive"

    assert act(c, csrf, ctx.a, "status", status="resolved").status_code == 303

    assert row(ctx.a)["status"] == "resolved" and audited("incident.status")


def test_missing_or_wrong_csrf_changes_nothing(ctx: Ctx) -> None:

    c, csrf = login("ann")

    for token in (None, "wrong", ""):
        assert act(c, token, ctx.a, "take").status_code == 403

    assert row(ctx.a)["owner"] is None

    bad = c.post(
        f"/incidents/{ctx.a}/take",
        content=urlencode({"csrf": csrf}),
        headers={**FORM, "origin": "https://evil.example"},
    )

    assert bad.status_code == 403 and row(ctx.a)["owner"] is None


def test_anonymous_viewer_and_unknown_incident(ctx: Ctx) -> None:

    anon = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)

    r = act(anon, "x", ctx.a, "take")

    assert (r.status_code, r.headers["location"]) == (303, "/login")

    v, vcsrf = login("viewer")

    assert act(v, vcsrf, ctx.a, "take").status_code == 403

    c, csrf = login("ann")

    gone = act(c, csrf, "nope", "take")

    assert gone.status_code == 404 and "text/html" in gone.headers["content-type"]

    assert row(ctx.a)["owner"] is None


def test_service_errors_show_on_the_page_not_as_500(ctx: Ctx) -> None:

    ann, acsrf = login("ann")

    bob, bcsrf = login("bob")

    act(ann, acsrf, ctx.a, "take")

    stale = act(bob, bcsrf, ctx.a, "take")  # already owned

    assert stale.status_code == 409 and "<form" in stale.text
    assert "<title>Error - " in stale.text  # a screen reader hears the title change

    other = act(bob, bcsrf, ctx.a, "disposition", disposition="false_positive")

    assert other.status_code == 403  # analyst on someone else's incident

    assert act(ann, acsrf, ctx.a, "status", status="resolved").status_code == 409  # no disposition

    assert row(ctx.a)["status"] == "in_progress"


def test_lead_assigns_merges_and_splits(ctx: Ctx) -> None:

    lead, csrf = login("lead")

    ann, acsrf = login("ann")

    assert act(ann, acsrf, ctx.a, "assign", owner="ann@example.test").status_code == 403

    assert act(lead, csrf, ctx.a, "assign", owner="ANN@example.test").status_code == 303

    assert row(ctx.a)["owner"] is not None

    assert act(lead, csrf, ctx.a, "assign", owner="ghost@example.test").status_code == 422

    assert act(lead, csrf, ctx.a, "split", alert=["a2"]).status_code == 303

    with closing(connect(config.DB_PATH)) as conn:
        assert conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 3

    assert act(lead, csrf, ctx.a, "split", alert=[]).status_code == 422

    r = act(lead, csrf, ctx.b, "merge", into=ctx.a)

    assert r.status_code == 303 and row(ctx.b)["merged_into"] == ctx.a

    assert audited("incident.merge") and audited("incident.split")


def test_hostile_text_is_escaped_everywhere(ctx: Ctx) -> None:

    lead, csrf = login("lead")

    act(lead, csrf, ctx.a, "comment", body=XSS)

    page = lead.get(f"/incidents/{ctx.a}").text

    assert XSS not in page and ESCAPED in page

    for action, field in (("assign", "owner"), ("merge", "into"), ("status", "status")):
        r = act(lead, csrf, ctx.a, action, **{field: XSS})

        assert r.status_code in (404, 409, 422) and XSS not in r.text, action

    r = act(lead, csrf, ctx.a, "split", alert=[XSS])

    assert r.status_code == 422 and XSS not in r.text


def test_oversize_form_is_refused(ctx: Ctx) -> None:

    c, csrf = login("ann")

    assert act(c, csrf, ctx.a, "take", junk="x" * 5000).status_code == 413
    assert act(c, csrf, ctx.a, "comment", body="x" * 40000).status_code == 413

    assert row(ctx.a)["owner"] is None


def test_alert_page_shows_escaped_raw_finding_and_404s(ctx: Ctx) -> None:

    c, _ = login("viewer")

    page = c.get("/alerts/a1")

    assert page.status_code == 200 and "Title R01" in page.text

    hostile = c.get("/alerts/b1").text

    assert XSS not in hostile and "&lt;script&gt;" in hostile

    gone = c.get("/alerts/nope")

    assert gone.status_code == 404 and "text/html" in gone.headers["content-type"]

    anon = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)

    assert anon.get("/alerts/a1").status_code == 303


def test_forms_are_shown_by_role_and_carry_the_token(ctx: Ctx) -> None:

    v, _ = login("viewer")

    assert f"/incidents/{ctx.a}/" not in v.get(f"/incidents/{ctx.a}").text

    a, csrf = login("ann")

    page = a.get(f"/incidents/{ctx.a}").text

    assert f'action="/incidents/{ctx.a}/take"' in page and f'value="{csrf}"' in page

    assert "/assign" not in page and "/split" not in page

    lead, _ = login("lead")

    page = lead.get(f"/incidents/{ctx.a}").text

    assert "/assign" in page and "/merge" in page and "/split" in page


def test_logout_ends_the_session(ctx: Ctx) -> None:

    c, csrf = login("ann")

    assert c.post("/logout", content=urlencode({"csrf": "wrong"}), headers=FORM).status_code == 403

    assert c.get("/").status_code == 200

    old = c.cookies["tl_session"]

    r = c.post("/logout", content=urlencode({"csrf": csrf}), headers=FORM)

    assert (r.status_code, r.headers["location"]) == (303, "/login")

    stale = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)

    stale.cookies.set("tl_session", old)

    assert stale.get("/").status_code == 303 and audited("logout")


def test_comment_with_newlines_and_accents_over_4kb_encoded_is_accepted(ctx: Ctx) -> None:
    c, csrf = login("ann")
    act(c, csrf, ctx.a, "take")
    body = "é\r\n" * 700  # 1,400 characters, about 7 KB once urlencoded
    assert act(c, csrf, ctx.a, "comment", body=body).status_code == 303


def test_alert_uid_with_a_slash_resolves(ctx: Ctx) -> None:

    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("UPDATE alerts SET finding_info_uid = 'x/y' WHERE id = 'a1'")

        conn.commit()

    c, _ = login("viewer")

    assert c.get("/alerts/x/y").status_code == 200


def test_buttons_follow_the_incident_state(ctx: Ctx) -> None:
    ann, acsrf = login("ann")
    lead, lcsrf = login("lead")
    act(ann, acsrf, ctx.a, "take")
    page = ann.get(f"/incidents/{ctx.a}").text
    assert "<option>resolved</option>" in page and "<option>in_progress</option>" not in page
    assert f"/incidents/{ctx.a}/take" not in page
    act(ann, acsrf, ctx.a, "disposition", disposition="false_positive")
    act(ann, acsrf, ctx.a, "status", status="resolved")
    done = ann.get(f"/incidents/{ctx.a}").text
    assert "/status" not in done and "/disposition" not in done and "/comment" in done
    reopen = lead.get(f"/incidents/{ctx.a}").text
    assert "<option>in_progress</option>" in reopen and "/split" not in reopen
    assert act(lead, lcsrf, ctx.a, "status", status="in_progress").status_code == 303


def test_stale_action_on_a_merged_incident_shows_the_message(ctx: Ctx) -> None:
    lead, lcsrf = login("lead")
    ann, acsrf = login("ann")
    assert act(lead, lcsrf, ctx.b, "merge", into=ctx.a).status_code == 303
    r = act(ann, acsrf, ctx.b, "take")
    assert r.status_code == 409 and "Error:" in r.text
