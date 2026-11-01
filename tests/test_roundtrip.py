"""Beacon -> ThreatLens -> beacon: findings in, analyst dispositions out as a verdicts CSV.

Beacon's own parser needs duckdb, which this project does not install. These tests restate its
rules (header, statuses, never 'new', no duplicates); scripts/roundtrip_beacon.py runs the real
`apply_verdicts` and `rule_performance` against a beacon checkout.
"""

from __future__ import annotations

import csv
import hashlib
import json
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app import cli, config
from app.db import connect, migrate
from app.ingest import ingest_findings
from app.users import User, create_user
from app.workflow import set_disposition, set_status, take

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "findings.jsonl"
BEACON_SCHEMA = ROOT.parent.parent / "beacon" / "contracts" / "detection-finding-v1.schema.json"
BEACON_STATUSES = {"triaged", "true_positive", "false_positive", "closed"}
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


def test_resolved_dispositions_come_out_as_a_valid_beacon_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "t.db"
    monkeypatch.setattr(config, "DB_PATH", db)
    migrate(db)
    findings = [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]
    with closing(connect(db)) as conn:
        ingest_findings(conn, findings, NOW, "test")
        uid = create_user(conn, "a@example.test", "correct horse battery", "analyst", NOW)
        user = User(uid, "a@example.test", "analyst")
        ids = [r[0] for r in conn.execute("SELECT id FROM incidents ORDER BY id")]
        assert len(ids) >= 3
        for iid, disposition in zip(
            ids[:3], ("true_positive", "false_positive", "benign_true_positive"), strict=True
        ):
            take(conn, user, iid, NOW)
            set_disposition(conn, user, iid, disposition, NOW)
            set_status(conn, user, iid, "resolved", NOW)
        conn.commit()
    out = tmp_path / "v.csv"
    assert cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) == 0
    with out.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["alert_id", "status", "reason"]
        rows = list(reader)
    uids = {f["finding_info"]["uid"] for f in findings}
    assert rows and {r["alert_id"] for r in rows} <= uids  # ids beacon exported
    assert len({r["alert_id"] for r in rows}) == len(rows)  # beacon rejects a repeated id
    assert {r["status"] for r in rows} <= BEACON_STATUSES  # and rejects 'new'
    assert {"true_positive", "false_positive", "closed"} <= {r["status"] for r in rows}


@pytest.mark.skipif(not BEACON_SCHEMA.exists(), reason="beacon checkout not next to this repo")
def test_vendored_schema_matches_beacons() -> None:
    ours = ROOT / "contracts" / "detection-finding-v1.schema.json"
    assert (
        hashlib.sha256(ours.read_bytes()).digest()
        == hashlib.sha256(BEACON_SCHEMA.read_bytes()).digest()
    )
