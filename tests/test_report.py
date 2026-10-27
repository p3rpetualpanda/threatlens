"""Incident report: HTML and Markdown, escaped, viewer+, merged or missing incidents are 404."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from incident_helpers import NOW, add, run

import app.main as main_mod
from app import config
from app.db import connect, migrate
from app.report import md
from app.users import create_user

PW = "correct horse battery"
XSS = "<script>alert(1)</script>"
LINK = "[click](http://evil.test) ![i](http://evil.test/x.png)"


@pytest.fixture
def iid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as conn:
        create_user(conn, "viewer@example.test", PW, "viewer", NOW)
        add(conn, "a", 0, host="h1", rule=XSS)
        add(conn, "b", 5, host="h1", rule="R02")
        (inc,) = run(conn)
        conn.execute("UPDATE incidents SET title = ?", [f"{XSS} {LINK}\n# heading"])
        conn.commit()
        yield inc


def login() -> TestClient:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    r = c.post(
        "/login",
        content=f"email=viewer@example.test&password={PW}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 303
    return c


def test_markdown_escapes_everything_it_prints(iid: str) -> None:
    r = login().get(f"/incidents/{iid}/report.md")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"]
    assert "<script>" not in r.text
    assert "](http://evil.test" not in r.text  # the link syntax is broken by a backslash
    assert "\n# heading" not in r.text
    assert "## Response checklist" in r.text and "## Disposition" in r.text


def test_html_page_is_escaped_and_has_the_sections(iid: str) -> None:
    r = login().get(f"/incidents/{iid}/report")
    assert r.status_code == 200
    assert "<script>alert" not in r.text
    assert "&lt;script&gt;" in r.text
    assert "Timeline" in r.text and "Actions taken" in r.text


def test_missing_and_merged_incidents_are_404(iid: str) -> None:
    c = login()
    assert c.get("/incidents/nope/report").status_code == 404
    assert c.get("/incidents/nope/report.md").status_code == 404
    with closing(connect(config.DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO incidents (id, environment, title, status, first_seen, last_seen, "
            "created_at, updated_at) SELECT 'other', environment, title, status, first_seen, "
            "last_seen, created_at, updated_at FROM incidents WHERE id = ?",
            [iid],
        )
        conn.execute("UPDATE incidents SET merged_into = 'other' WHERE id = ?", [iid])
        conn.commit()
    assert c.get(f"/incidents/{iid}/report").status_code == 404
    assert c.get(f"/incidents/{iid}/report.md").status_code == 404


def test_md_flattens_lines_and_escapes_markup() -> None:
    assert md("a\n# b | *c*") == r"a \# b \| \*c\*"
