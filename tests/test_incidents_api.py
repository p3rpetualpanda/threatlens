from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import config
from app.db import connect, migrate
from app.ingest import ingest_findings
from app.users import create_user

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    findings = [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]
    with closing(connect(db)) as conn:
        create_user(conn, "v@example.test", "correct horse battery", "viewer", NOW)
        ingest_findings(conn, findings, NOW)
    c = TestClient(main_mod.app, base_url="http://localhost")
    assert c.post(
        "/api/v1/login", json={"email": "v@example.test", "password": "correct horse battery"}
    ).is_success
    yield c


def test_list_filters_by_environment(client: TestClient) -> None:
    both = client.get("/api/v1/incidents").json()["incidents"]
    assert len(both) == 3
    lab_a = client.get("/api/v1/incidents", params={"environment": "lab_a"}).json()["incidents"]
    assert [(i["environment"], i["alert_count"]) for i in lab_a] == [("lab_a", 2)]


def test_list_filters_by_status_and_rejects_unknown(client: TestClient) -> None:
    assert client.get("/api/v1/incidents", params={"status": "resolved"}).json() == {
        "incidents": []
    }
    assert client.get("/api/v1/incidents", params={"status": "bogus"}).status_code == 422


def test_limit_is_capped_at_200(client: TestClient) -> None:
    assert client.get("/api/v1/incidents", params={"limit": 2}).json()["incidents"].__len__() == 2
    assert client.get("/api/v1/incidents", params={"limit": 201}).status_code == 422
    assert client.get("/api/v1/incidents", params={"limit": 0}).status_code == 422


def test_sql_in_filter_is_just_a_value(client: TestClient) -> None:
    resp = client.get("/api/v1/incidents", params={"environment": "x' OR '1'='1"})
    assert resp.json() == {"incidents": []}


def test_detail_explains_membership(client: TestClient) -> None:
    lab_a = client.get("/api/v1/incidents", params={"environment": "lab_a"}).json()["incidents"][0]
    detail = client.get(f"/api/v1/incidents/{lab_a['id']}").json()
    assert detail["alert_count"] == 2
    assert {a["rule"] for a in detail["alerts"]} == {"R05", "R01"}
    assert any("shares host `scranton`" in a["why"] for a in detail["alerts"])


def test_detail_folds_same_rule_repeats(client: TestClient) -> None:
    with closing(connect(config.DB_PATH)) as conn:
        findings = [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]
        again = json.loads(json.dumps(findings[0]))
        again["finding_info"]["uid"] = "f0000000000000000000000000000099"
        ingest_findings(conn, [again], NOW)
    lab_a = client.get("/api/v1/incidents", params={"environment": "lab_a"}).json()["incidents"][0]
    detail = client.get(f"/api/v1/incidents/{lab_a['id']}").json()
    assert detail["alert_count"] == 3
    r05 = next(a for a in detail["alerts"] if a["rule"] == "R05")
    assert (r05["count"], len(r05["uids"])) == (2, 2)
    assert len(detail["alerts"]) == 2


def test_unknown_incident_is_404(client: TestClient) -> None:
    assert client.get("/api/v1/incidents/nope").status_code == 404
