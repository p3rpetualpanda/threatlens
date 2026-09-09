from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


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


def test_unknown_alert_returns_404():
    assert client.get("/api/alerts/missing").status_code == 404
