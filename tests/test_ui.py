from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

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


@pytest.fixture
def iid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as conn:
        create_user(conn, "viewer@example.test", PW, "viewer", NOW)
        create_user(conn, f"{XSS}@example.test", PW, "analyst", NOW)
        add(conn, "a", 0, host=XSS, user="bob", rule=XSS)
        add(conn, "b", 5, host=XSS, rule="R02")
        conn.execute("UPDATE alerts SET technique = 'T1001'")
        conn.execute(
            "INSERT INTO alert_entities (id, alert_id, kind, value) "
            "VALUES ('ip1', 'a', 'src_ip', '8.8.8.8')"
        )
        conn.execute("INSERT INTO assets VALUES ('e', ?, 3, '', '')", [XSS.lower()])
        conn.execute("INSERT INTO identities VALUES ('e', 'bob', 1, '')")
        (inc,) = run(conn)
        conn.execute("UPDATE incidents SET title = ?", [XSS])
        conn.execute(
            "INSERT INTO comments (id, incident_id, author, body, created_at) "
            "VALUES ('c1', ?, ?, ?, ?)",
            [inc, XSS, XSS, NOW.isoformat()],
        )
        conn.commit()
        yield inc


def login(email: str = "viewer@example.test") -> TestClient:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    r = c.post(
        "/login",
        content=f"email={email}&password={PW}".replace("<", "%3C"),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 303, r.text
    return c


def test_anonymous_is_sent_to_login(iid: str) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    for path in ("/", f"/incidents/{iid}"):
        r = c.get(path)
        assert (r.status_code, r.headers["location"]) == (303, "/login")


def test_login_form_and_bad_password(iid: str) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    assert 'name="password"' in c.get("/login").text
    r = c.post(
        "/login",
        content="email=viewer@example.test&password=nope",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 401 and "invalid email or password" in r.text
    assert "tl_session" not in r.cookies


def test_login_sets_the_session_cookie_and_queue_lists_the_incident(iid: str) -> None:
    c = login()
    page = c.get("/")
    assert page.status_code == 200
    assert f'href="/incidents/{iid}"' in page.text
    assert "Medium" in page.text or "Low" in page.text
    assert c.get("/?status=resolved").text.count("/incidents/") == 0


def test_queue_filters_are_validated(iid: str) -> None:
    c = login()
    assert c.get("/?status=bogus").status_code == 422
    assert c.get("/?limit=9999").status_code == 422


def test_detail_shows_why_timeline_entities_and_comments(iid: str) -> None:
    page = login().get(f"/incidents/{iid}").text
    assert "attack.mitre.org/techniques/T1001" in page
    assert "Data Obfuscation" in page
    assert "public" in page  # IP class badge for 8.8.8.8
    assert "criticality 3" in page and "privileged" in page
    assert "Timeline" in page and "Risk factors" in page


def test_unknown_incident_is_404(iid: str) -> None:
    assert login().get("/incidents/nope").status_code == 404


def test_every_page_escapes_hostile_values(iid: str) -> None:
    c = login()
    for path in ("/", f"/incidents/{iid}"):
        text = c.get(path).text
        assert XSS not in text, path
        assert ESCAPED in text, path


def test_technique_link_must_be_https_attack_mitre(
    iid: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import attack

    monkeypatch.setattr(
        attack,
        "describe",
        lambda t: {"id": t, "name": "x", "tactics": [], "url": "javascript:alert(1)"},
    )
    page = login().get(f"/incidents/{iid}").text
    assert "javascript:" not in page


def test_css_is_served_and_pages_have_no_inline_script(iid: str) -> None:
    c = login()
    assert c.get("/static/app.css").headers["content-type"].startswith("text/css")
    assert "<script" not in c.get("/").text
    assert " style=" not in c.get(f"/incidents/{iid}").text
    assert json.loads(c.get("/api/v1/me").text)["user"]["role"] == "viewer"


FORM = {"content-type": "application/x-www-form-urlencoded"}


def _post(c: TestClient, body: str, **extra: str) -> httpx.Response:
    r: httpx.Response = c.post("/login", content=body, headers={**FORM, **extra})
    return r


def test_form_login_refuses_a_cross_site_origin(iid: str) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    body = f"email=viewer@example.test&password={PW}"
    bad = _post(c, body, origin="https://evil.example")
    assert bad.status_code == 403 and "tl_session" not in bad.cookies
    assert _post(c, body, origin="http://localhost").status_code == 303


def test_form_login_throttle_sends_retry_after(iid: str) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    for _ in range(8):
        r = _post(c, "email=viewer@example.test&password=nope")
    assert r.status_code == 429 and "retry-after" in r.headers


def test_form_login_caps_a_body_without_content_length(iid: str) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)

    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b"x" * 1000

    r = c.post("/login", content=chunks(), headers=FORM)  # chunked: no Content-Length
    assert r.status_code == 413


def test_any_status_filter_and_html_404_and_merged_redirect(iid: str) -> None:
    c = login()
    assert c.get("/?status=&environment=&owner=").status_code == 200
    gone = c.get("/incidents/nope")
    assert gone.status_code == 404 and "text/html" in gone.headers["content-type"]
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO incidents (id, environment, title, merged_into, created_at, updated_at) "
            "VALUES ('old', 'e', 't', ?, ?, ?)",
            [iid, NOW.isoformat(), NOW.isoformat()],
        )
        conn.commit()
    r = c.get("/incidents/old")
    assert (r.status_code, r.headers["location"]) == (303, f"/incidents/{iid}")


def _mk(conn: object, iid: str, score: int | None, seen: str, env: str = "e") -> None:
    conn.execute(  # type: ignore[attr-defined]
        "INSERT INTO incidents (id, environment, title, risk_score, last_seen, created_at, "
        "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [iid, env, iid, score, seen, NOW.isoformat(), NOW.isoformat()],
    )


def test_queue_sort_filters_limit_and_merged(iid: str) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute("UPDATE incidents SET risk_score = 40, last_seen = '2026-01-01'")
        _mk(conn, "hi", 90, "2026-01-01")
        _mk(conn, "none", None, "2026-03-01")
        _mk(conn, "tie-new", 40, "2026-02-01", env="other")
        _mk(conn, "gone", 99, "2026-01-01")
        conn.execute("UPDATE incidents SET merged_into = ? WHERE id = 'gone'", [iid])
        conn.execute("UPDATE incidents SET status = 'resolved' WHERE id = 'hi'")
        owner = conn.execute("SELECT id FROM users WHERE role = 'analyst'").fetchone()[0]
        conn.execute("UPDATE incidents SET owner = ? WHERE id = 'tie-new'", [owner])
        conn.commit()
    c = login()

    def order(q: str) -> list[str]:
        text = c.get(q).text
        return [x.split('"')[0] for x in text.split('href="/incidents/')[1:]]

    assert order("/") == ["hi", "tie-new", iid, "none"]  # score desc, then last_seen, NULL last
    assert order("/?limit=1") == ["hi"]
    assert order("/?status=resolved") == ["hi"]
    assert order("/?environment=other") == ["tie-new"]
    assert order(f"/?owner={XSS}@EXAMPLE.test".replace("<", "%3C")) == ["tie-new"]
    assert order("/?owner=nobody@example.test") == []
    assert "gone" not in order("/")


def test_filter_echo_and_header_email_are_escaped(iid: str) -> None:
    c = login(f"{XSS}@example.test")
    page = c.get('/?environment="><script>alert(1)</script>').text
    assert '"><script>' not in page and "&#34;&gt;&lt;script&gt;" in page
    assert ESCAPED in page  # the signed-in email in the header
