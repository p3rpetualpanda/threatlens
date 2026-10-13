from datetime import datetime, timedelta, timezone

from app.data import seed_events
from app.detection import detect
from app.models import SecurityEvent


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


def test_failed_logins_within_ten_minutes_trigger_alert():
    start = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            event_id="failure-%d" % index,
            timestamp=start + timedelta(minutes=index * 2.5),
            event_type="authentication",
            source_ip="203.0.113.55",
            outcome="failure",
        )
        for index in range(5)
    ]

    assert any(alert.technique_id == "T1110" for alert in detect(events))


def test_failed_logins_outside_ten_minutes_do_not_trigger_alert():
    start = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            event_id="failure-%d" % index,
            timestamp=start + timedelta(minutes=index * 3),
            event_type="authentication",
            source_ip="203.0.113.55",
            outcome="failure",
        )
        for index in range(5)
    ]

    assert not any(alert.technique_id == "T1110" for alert in detect(events))
