"""Metrics: alert-to-incident reduction, MTTA, MTTR and dispositions per rule (spec 6.7 item 5)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from incident_helpers import NOW, add, run

import app.main as main_mod
from app import config
from app.audit import record
from app.db import connect, migrate
from app.metrics import build
from app.users import create_user

PW = "correct horse battery"
XSS = "<script>alert(1)</script>"


@pytest.fixture
def conn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[sqlite3.Connection]:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    with closing(connect(db)) as c:
        yield c


def _two_incidents(conn: sqlite3.Connection, rule_a: str = "R01") -> tuple[str, str]:
    """Alerts a, b share a host (one incident); c is alone (a second). Returns their ids."""
    add(conn, "a", 0, host="h1", rule=rule_a)
    add(conn, "b", 5, host="h1", rule=rule_a)
    add(conn, "c", 10, host="h2", rule="R02")
    ids = run(conn)
    by_size = {
        r["incident_id"]: r["n"]
        for r in conn.execute("SELECT incident_id, COUNT(*) n FROM incident_alerts GROUP BY 1")
    }
    big = max(ids, key=lambda i: by_size[i])
    return big, next(i for i in ids if i != big)


def _audit(conn: sqlite3.Connection, action: str, iid: str, hours: float, detail=None) -> None:  # type: ignore[no-untyped-def]
    record(conn, "x@example.test", action, iid, detail, NOW + timedelta(hours=hours))
    conn.commit()


def test_empty_database_has_no_numbers_and_no_division_by_zero(conn: sqlite3.Connection) -> None:
    m = build(conn)
    assert (m["alerts"], m["incidents"]) == (0, 0)
    assert m["reduction"] is None and m["mtta_hours"] is None and m["mttr_hours"] is None
    assert m["rules"] == []


def test_reduction_is_alerts_per_live_incident(conn: sqlite3.Connection) -> None:
    _two_incidents(conn)
    m = build(conn)
    assert (m["alerts"], m["incidents"], m["reduction"]) == (3, 2, 1.5)


def test_merged_away_incident_is_not_counted(conn: sqlite3.Connection) -> None:
    big, small = _two_incidents(conn)
    conn.execute("UPDATE incidents SET merged_into = ? WHERE id = ?", [big, small])
    conn.commit()
    assert build(conn)["incidents"] == 1


def test_mtta_averages_first_owner_time_and_ignores_unassign(conn: sqlite3.Connection) -> None:
    big, small = _two_incidents(conn)
    _audit(conn, "incident.take", big, 1)
    _audit(conn, "incident.assign", big, 9, {"from": None, "to": "u2"})  # later, not the first
    _audit(conn, "incident.assign", small, 2, {"from": None, "to": None})  # unassign: not an owner
    _audit(conn, "incident.assign", small, 5, {"from": None, "to": "u2"})
    assert build(conn)["mtta_hours"] == 3.0  # (1 + 5) / 2


def test_mtta_is_none_when_nobody_took_anything(conn: sqlite3.Connection) -> None:
    _two_incidents(conn)
    assert build(conn)["mtta_hours"] is None


def test_mttr_uses_only_resolved_incidents(conn: sqlite3.Connection) -> None:
    big, _ = _two_incidents(conn)
    when = (NOW + timedelta(hours=4)).isoformat()
    conn.execute("UPDATE incidents SET status='resolved', resolved_at=? WHERE id=?", [when, big])
    conn.commit()
    assert build(conn)["mttr_hours"] == 4.0


def test_rules_count_dispositions_on_resolved_incidents_only(conn: sqlite3.Connection) -> None:
    big, small = _two_incidents(conn)  # big holds two R01 alerts, small one R02
    conn.execute(
        "UPDATE incidents SET status='resolved', disposition='false_positive' WHERE id=?", [big]
    )
    conn.execute("UPDATE incidents SET disposition='true_positive' WHERE id=?", [small])  # open
    conn.commit()
    rules = {r["rule"]: r for r in build(conn)["rules"]}
    assert rules["R01"]["false_positive"] == 2 and rules["R01"]["fp_rate"] == 1.0
    assert rules["R02"]["alerts"] == 1 and rules["R02"]["fp_rate"] is None  # nothing resolved yet


def test_fp_rate_is_false_positives_over_dispositioned(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h1")
    add(conn, "b", 1000, host="h2")  # far apart: separate incidents
    ids = run(conn)
    for iid, disp in zip(ids, ("false_positive", "true_positive"), strict=True):
        conn.execute(
            "UPDATE incidents SET status='resolved', disposition=? WHERE id=?", [disp, iid]
        )
    conn.commit()
    (r,) = build(conn)["rules"]
    assert (r["false_positive"], r["true_positive"], r["fp_rate"]) == (1, 1, 0.5)


def _client(conn: sqlite3.Connection, role: str = "viewer") -> TestClient:
    create_user(conn, f"{role}@example.test", PW, role, NOW)
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    r = c.post(
        "/login",
        content=f"email={role}@example.test&password={PW}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 303
    return c


def test_page_shows_numbers_and_escapes_rule_names(conn: sqlite3.Connection) -> None:
    _two_incidents(conn, rule_a=XSS)
    r = _client(conn).get("/metrics")
    assert r.status_code == 200
    assert "1.5 (3 alerts, 2 incidents)" in r.text
    assert "0 of 2 incidents acknowledged, 2 waiting" in r.text
    assert "&lt;script&gt;" in r.text and "<script>alert" not in r.text
    assert 'href="/metrics"' in r.text  # the nav link


def test_alerts_in_no_incident_are_not_counted(conn: sqlite3.Connection) -> None:
    _two_incidents(conn)
    add(conn, "orphan", 3000, host="h9")  # ingested but not correlated yet
    conn.commit()
    m = build(conn)
    assert (m["alerts"], m["reduction"]) == (3, 1.5)


def test_unacknowledged_counts_incidents_nobody_took(conn: sqlite3.Connection) -> None:
    big, _ = _two_incidents(conn)
    _audit(conn, "incident.take", big, 1)
    assert build(conn)["unacknowledged"] == 1


def test_malformed_audit_detail_does_not_break_the_page(conn: sqlite3.Connection) -> None:
    big, _ = _two_incidents(conn)
    conn.execute(
        "INSERT INTO audit_log (at, actor, action, target, detail, prev_hash, hash) "
        "VALUES (?, 'x', 'incident.assign', ?, 'not json', 'p', 'h')",
        [(NOW + timedelta(hours=1)).isoformat(), big],
    )
    conn.commit()
    assert build(conn)["mtta_hours"] is None


def test_merged_away_incident_leaves_mtta_mttr_and_rules(conn: sqlite3.Connection) -> None:
    big, small = _two_incidents(conn)  # small holds the lone R02 alert
    _audit(conn, "incident.take", small, 1)
    conn.execute(
        "UPDATE incidents SET status='resolved', disposition='true_positive', resolved_at=?, "
        "merged_into=? WHERE id=?",
        [(NOW + timedelta(hours=3)).isoformat(), big, small],
    )
    conn.commit()
    m = build(conn)
    assert m["mtta_hours"] is None and m["mttr_hours"] is None
    assert m["rules"][0]["true_positive"] == 0


def test_resolved_without_a_timestamp_is_left_out_of_mttr(conn: sqlite3.Connection) -> None:
    big, _ = _two_incidents(conn)
    conn.execute("UPDATE incidents SET status='resolved' WHERE id=?", [big])
    conn.commit()
    assert build(conn)["mttr_hours"] is None


def test_page_on_an_empty_database_says_not_enough_data(conn: sqlite3.Connection) -> None:
    r = _client(conn).get("/metrics")
    assert r.status_code == 200 and "n/a" in r.text


def test_anonymous_is_sent_to_login(conn: sqlite3.Connection) -> None:
    c = TestClient(main_mod.app, base_url="http://localhost", follow_redirects=False)
    assert c.get("/metrics").status_code == 303
