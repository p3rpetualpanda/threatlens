import pytest

from app.data import seed_events
from app.models import AlertUpdate
from app.store import SQLiteStore


def test_empty_database_is_seeded_once(tmp_path):
    store = SQLiteStore(tmp_path / "threatlens.db")

    assert len(store.list_alerts()) >= 3


def test_events_and_alert_status_persist_across_store_instances(tmp_path):
    database_path = tmp_path / "threatlens.db"
    first_store = SQLiteStore(database_path)
    alert_id = first_store.list_alerts()[0].alert_id
    first_store.update_alert(alert_id, AlertUpdate(status="resolved"))

    second_store = SQLiteStore(database_path)

    assert second_store.get_alert(alert_id).status == "resolved"


def test_added_event_persists_and_recomputes_alerts(tmp_path):
    database_path = tmp_path / "threatlens.db"
    first_store = SQLiteStore(database_path)
    event = seed_events()[-1].model_copy(update={"event_id": "persisted-network-event"})

    alerts = first_store.add_event(event)
    second_store = SQLiteStore(database_path)

    assert any(alert.alert_id == "exfiltration-persisted-network-event" for alert in alerts)
    assert any(alert.alert_id == "exfiltration-persisted-network-event" for alert in second_store.list_alerts())


def test_duplicate_event_id_raises_value_error(tmp_path):
    store = SQLiteStore(tmp_path / "threatlens.db")
    event = seed_events()[-1].model_copy(update={"event_id": "duplicate-event"})

    store.add_event(event)

    with pytest.raises(ValueError, match="Event ID already exists"):
        store.add_event(event)


def test_alert_status_survives_add_event_recompute(tmp_path):
    store = SQLiteStore(tmp_path / "threatlens.db")
    alert_id = "exfiltration-net-001"
    store.update_alert(alert_id, AlertUpdate(status="resolved"))
    event = seed_events()[-1].model_copy(update={"event_id": "recompute-network-event"})

    store.add_event(event)

    assert store.get_alert(alert_id).status == "resolved"
