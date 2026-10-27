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
from app.users import create_user

PW = "correct horse battery"


@pytest.fixture
def ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as conn:
        for role in ("analyst", "lead"):
            create_user(conn, f"{role}@example.test", PW, role, NOW)
        add(conn, "a", 0, host="h")
        add(conn, "b", 5, host="h", rule="R02")
        yield run(conn)[0]


def login(role: str) -> TestClient:
    c = TestClient(main_mod.app, base_url="http://localhost")
    r = c.post("/api/v1/login", json={"email": f"{role}@example.test", "password": PW})
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def test_analyst_flow_over_http(ids: str) -> None:
    c = login("analyst")
    base = f"/api/v1/incidents/{ids}"
    assert c.post(f"{base}/take").json()["status"] == "in_progress"
    assert c.post(f"{base}/take").status_code == 409
    assert c.post(f"{base}/status", json={"status": "resolved"}).status_code == 409
    assert c.post(f"{base}/disposition", json={"disposition": "false_positive"}).is_success
    assert c.post(f"{base}/status", json={"status": "resolved"}).json()["status"] == "resolved"
    assert c.post(f"{base}/comments", json={"body": "<script>x</script>"}).is_success
    detail = c.get(base).json()
    assert detail["owner_email"] == "analyst@example.test"
    assert [x["body"] for x in detail["comments"]] == ["<script>x</script>"]


def test_lead_split_and_merge_over_http(ids: str) -> None:
    c = login("lead")
    new_id = c.post(f"/api/v1/incidents/{ids}/split", json={"alerts": ["b"]}).json()["id"]
    assert c.get(f"/api/v1/incidents/{new_id}").json()["alert_count"] == 1
    merged = c.post(f"/api/v1/incidents/{new_id}/merge", json={"into": ids})
    assert merged.json()["id"] == ids
    assert c.get(f"/api/v1/incidents/{ids}").json()["alert_count"] == 2
    gone = c.post(f"/api/v1/incidents/{new_id}/comments", json={"body": "late"})
    assert gone.status_code == 409


def test_errors_roll_back_and_validate(ids: str) -> None:
    c = login("lead")
    base = f"/api/v1/incidents/{ids}"
    assert c.post(f"{base}/assign", json={"owner": "ghost@example.test"}).status_code == 422
    assert c.post(f"{base}/comments", json={"body": "x" * 7000}).status_code == 422
    assert c.get(base).json()["comments"] == []
