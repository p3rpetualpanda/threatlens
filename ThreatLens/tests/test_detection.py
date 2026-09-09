from app.data import seed_events
from app.detection import detect


def test_seed_data_produces_explainable_alerts():
    alerts = detect(seed_events())
    titles = {alert.title for alert in alerts}

    assert "Repeated authentication failures" in titles
    assert "Encoded or remote PowerShell execution" in titles
    assert "Unusually large outbound transfer" in titles
    assert all(alert.evidence for alert in alerts)
    assert all(0 <= alert.confidence <= 1 for alert in alerts)


def test_failed_logins_below_threshold_do_not_alert():
    events = seed_events()[:4]
    assert not any(alert.technique_id == "T1110" for alert in detect(events))
