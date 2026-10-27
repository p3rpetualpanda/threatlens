import time

from app import flash


def test_a_message_is_read_once_and_only_by_its_own_session() -> None:
    flash.put("s1", "done", "take")
    assert flash.pop("s2", "done") is None
    assert flash.pop("s1", "done") == "take"
    assert flash.pop("s1", "done") is None


def test_an_expired_message_is_dropped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    flash.put("s1", "done", "take")
    monkeypatch.setattr(time, "monotonic", lambda: 10_000_000.0)
    assert flash.pop("s1", "done") is None
