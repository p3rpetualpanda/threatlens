from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from incident_helpers import NOW, add, run

from app.cli import main
from app.db import connect, migrate
from app.enrich import ip_class, load_assets, load_identities


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    migrate(path)
    with closing(connect(path)) as c:
        yield c


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("10.1.2.3", "private"),
        ("192.168.0.9", "private"),
        ("169.254.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("203.0.113.5", "documentation"),
        ("198.51.100.7", "documentation"),
        ("192.0.2.10", "documentation"),
        ("2001:db8::1", "documentation"),
        ("8.8.8.8", "public"),
        ("2606:4700::1111", "public"),
        (" 8.8.8.8 ", "public"),
        ("100.64.1.1", "private"),
        ("::ffff:8.8.8.8", "public"),
        ("::ffff:10.0.0.1", "private"),
        ("not-an-ip", "unknown"),
        ("", "unknown"),
    ],
)
def test_ip_class(value: str, want: str) -> None:
    assert ip_class(value) == want


def csv(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "x.csv"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_assets_lowercases_and_replaces(conn: sqlite3.Connection, tmp_path: Path) -> None:
    p = csv(tmp_path, "# note\nenvironment,host,criticality,owner,role\ne,SRV1,3,ops,dc\n")
    assert load_assets(conn, p, NOW) == 1
    p = csv(tmp_path, "environment,host,criticality,owner,role\ne,srv2,2,,\n")
    assert load_assets(conn, p, NOW) == 1
    assert [tuple(r) for r in conn.execute("SELECT host, criticality FROM assets")] == [("srv2", 2)]
    assert (
        conn.execute("SELECT count(*) FROM audit_log WHERE action='assets.load'").fetchone()[0] == 2
    )


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("environment,host\ne,h\n", "header"),
        ("environment,host,criticality,owner,role\n", "no rows"),
        ("environment,host,criticality,owner,role\ne,h,4,,\n", "criticality"),
        ("environment,host,criticality,owner,role\ne,,1,,\n", "required"),
        ("environment,host,criticality,owner,role\ne,H,1,,\ne,h,2,,\n", "duplicate"),
        ("environment,host,criticality,owner,role\ne,h,2\n", "columns"),
        ("environment,host,criticality,owner,role\ne,h,2,a,b,c\n", "columns"),
    ],
)
def test_bad_assets_are_refused_and_keep_old_rows(
    conn: sqlite3.Connection, tmp_path: Path, text: str, msg: str
) -> None:
    load_assets(conn, csv(tmp_path, "environment,host,criticality,owner,role\ne,keep,1,,\n"), NOW)
    with pytest.raises(ValueError, match=msg):
        load_assets(conn, csv(tmp_path, text), NOW)
    assert conn.execute("SELECT host FROM assets").fetchall()[0][0] == "keep"


def test_load_identities_and_bad_flag(conn: sqlite3.Connection, tmp_path: Path) -> None:
    head = "environment,user,privileged,department\n"
    assert load_identities(conn, csv(tmp_path, head + "e,Admin,Yes,it\ne,bob,0,\n"), NOW) == 2
    rows = conn.execute("SELECT user, privileged FROM identities ORDER BY user").fetchall()
    assert [tuple(r) for r in rows] == [("admin", 1), ("bob", 0)]
    with pytest.raises(ValueError, match="privileged"):
        load_identities(conn, csv(tmp_path, head + "e,x,maybe,\n"), NOW)


def test_missing_file_is_a_value_error(conn: sqlite3.Connection, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        load_assets(conn, tmp_path / "nope.csv", NOW)


def factors(conn: sqlite3.Connection, iid: str) -> list[str]:
    row = conn.execute("SELECT risk_factors FROM incidents WHERE id=?", [iid]).fetchone()
    return [f["factor"] for f in json.loads(row[0])]


def test_new_factors_apply_and_rescore_picks_up_new_csvs(
    conn: sqlite3.Connection, tmp_path: Path
) -> None:
    from app.incidents import rescore

    add(conn, "a", 0, host="SRV1", user="Admin")
    conn.execute("UPDATE alerts SET tactic = 'Credential Access' WHERE id = 'a'")
    conn.execute(
        "INSERT INTO alert_entities (id, alert_id, kind, value) "
        "VALUES ('x', 'a', 'src_ip', '8.8.8.8')"
    )
    (iid,) = run(conn)
    assert factors(conn, iid) == ["severity", "progress", "public_ip"]
    load_assets(conn, csv(tmp_path, "environment,host,criticality,owner,role\ne,srv1,3,,\n"), NOW)
    load_identities(
        conn, csv(tmp_path, "environment,user,privileged,department\ne,admin,true,\n"), NOW
    )
    assert rescore(conn, NOW) == [iid]
    assert factors(conn, iid) == ["severity", "progress", "asset", "privileged", "public_ip"]
    assert rescore(conn, NOW) == []  # nothing changed the second time


def test_documentation_ip_and_non_auth_alert_do_not_score(conn: sqlite3.Connection) -> None:
    add(conn, "a", 0, host="h")
    add(conn, "b", 5, host="h")
    conn.execute("UPDATE alerts SET tactic = 'Credential Access' WHERE id = 'a'")
    conn.execute("UPDATE alerts SET tactic = 'Execution' WHERE id = 'b'")
    for uid, ip in (("a", "203.0.113.5"), ("b", "8.8.8.8")):
        conn.execute(
            "INSERT INTO alert_entities (id, alert_id, kind, value) VALUES (?, ?, 'src_ip', ?)",
            [f"e{uid}", uid, ip],
        )
    (iid,) = run(conn)
    assert "public_ip" not in factors(conn, iid)


def test_cli_loads_and_rescores(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "c.db"
    p = csv(tmp_path, "environment,host,criticality,owner,role\ne,h,2,,\n")
    assert main(["load-assets", str(p), "--db", str(db)]) == 0
    assert "loaded 1 rows; re-scored 0 incidents" in capsys.readouterr().out
    bad = csv(tmp_path, "nope\n")
    assert main(["load-identities", str(bad), "--db", str(db)]) == 1
    assert "header" in capsys.readouterr().err


def test_shipped_demo_csvs_load(conn: sqlite3.Connection) -> None:
    root = Path(__file__).resolve().parent.parent / "config"
    assert load_assets(conn, root / "assets.csv", NOW) == 2
    assert load_identities(conn, root / "identities.csv", NOW) == 2


def test_load_audit_records_file_hash(conn: sqlite3.Connection, tmp_path: Path) -> None:
    text = "environment,host,criticality,owner,role\ne,h,1,,\n"
    load_assets(conn, csv(tmp_path, text), NOW)
    detail = conn.execute("SELECT detail FROM audit_log WHERE action = 'assets.load'").fetchone()[0]
    assert '"sha256"' in detail and "x.csv" in detail
