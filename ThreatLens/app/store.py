from typing import Dict, List

from .data import seed_events
from .detection import detect
from .models import Alert, AlertUpdate, SecurityEvent


class InMemoryStore:
    def __init__(self) -> None:
        self.events: List[SecurityEvent] = seed_events()
        self.alerts: Dict[str, Alert] = {alert.alert_id: alert for alert in detect(self.events)}

    def list_alerts(self) -> List[Alert]:
        return sorted(self.alerts.values(), key=lambda item: item.last_seen, reverse=True)

    def get_alert(self, alert_id: str) -> Alert:
        if alert_id not in self.alerts:
            raise KeyError(alert_id)
        return self.alerts[alert_id]

    def update_alert(self, alert_id: str, update: AlertUpdate) -> Alert:
        alert = self.get_alert(alert_id)
        self.alerts[alert_id] = alert.model_copy(update={"status": update.status})
        return self.alerts[alert_id]
