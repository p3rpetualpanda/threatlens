from datetime import datetime, timedelta, timezone
from typing import List

from .models import SecurityEvent


def seed_events() -> List[SecurityEvent]:
    """Return deterministic, safe synthetic events for demos and tests."""
    start = datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
    events: List[SecurityEvent] = []
    for index in range(6):
        events.append(
            SecurityEvent(
                event_id="auth-fail-%d" % index,
                timestamp=start + timedelta(minutes=index),
                event_type="authentication",
                source_ip="203.0.113.44",
                username="admin",
                host="gateway-01",
                action="login",
                outcome="failure",
            )
        )
    events.extend(
        [
            SecurityEvent(
                event_id="auth-success-1",
                timestamp=start + timedelta(minutes=20),
                event_type="authentication",
                source_ip="198.51.100.12",
                username="j.smith",
                host="vpn-01",
                action="login",
                outcome="success",
            ),
            SecurityEvent(
                event_id="auth-success-2",
                timestamp=start + timedelta(minutes=45),
                event_type="authentication",
                source_ip="192.0.2.88",
                username="j.smith",
                host="vpn-01",
                action="login",
                outcome="success",
            ),
            SecurityEvent(
                event_id="proc-001",
                timestamp=start + timedelta(hours=1),
                event_type="process",
                source_ip="10.0.0.24",
                host="workstation-24",
                username="j.smith",
                command="powershell.exe -enc SQBFAFgA",
            ),
            SecurityEvent(
                event_id="net-001",
                timestamp=start + timedelta(hours=2),
                event_type="network",
                source_ip="10.0.0.24",
                host="workstation-24",
                bytes_sent=75000000,
                metadata={"destination": "198.51.100.200", "protocol": "https"},
            ),
        ]
    )
    return events
