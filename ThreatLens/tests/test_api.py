import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.store import SQLiteStore


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "store", SQLiteStore(tmp_path / "threatlens.db"))


client = TestClient(main_module.app)


def test_health_and_alert_listing():
    assert client.get("/health").json() == {"status": "ok"}
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert len(response.json()) >= 3


def test_alert_status_can_be_updated():
    alert_id = client.get("/api/alerts").json()[0]["alert_id"]
    response = client.patch("/api/alerts/" + alert_id, json={"status": "investigating"})
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


def test_invalid_alert_status_returns_422():
    alert_id = client.get("/api/alerts").json()[0]["alert_id"]
    response = client.patch("/api/alerts/" + alert_id, json={"status": "bogus"})
    assert response.status_code == 422


def test_event_ingestion_recomputes_alerts():
    response = client.post(
        "/api/events",
        json={
            "event_id": "new-network-event",
            "timestamp": "2026-01-15T12:00:00+00:00",
            "event_type": "network",
            "source_ip": "10.0.0.30",
            "bytes_sent": 60000000,
        },
    )

    assert response.status_code == 201
    assert any(alert["alert_id"] == "exfiltration-new-network-event" for alert in response.json())


def test_duplicate_event_id_returns_409():
    event = {
        "event_id": "duplicate-event",
        "timestamp": "2026-01-15T12:00:00+00:00",
        "event_type": "network",
        "source_ip": "10.0.0.30",
        "bytes_sent": 1,
    }
    assert client.post("/api/events", json=event).status_code == 201

    response = client.post("/api/events", json=event)

    assert response.status_code == 409


def test_unknown_alert_returns_404():
    assert client.get("/api/alerts/missing").status_code == 404
