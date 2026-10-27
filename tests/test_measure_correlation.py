from __future__ import annotations

import json
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.db import connect, migrate
from app.ingest import ingest_findings

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import measure_correlation

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"


def test_measure_prints_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "t.db"
    migrate(db)
    findings = [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]
    with closing(connect(db)) as conn:
        ingest_findings(conn, findings, datetime(2026, 10, 25, tzinfo=UTC))
    assert measure_correlation.main(["measure", str(db)]) == 0
    out = capsys.readouterr().out
    assert "alerts: 4" in out
    assert "incidents: 3" in out
    assert "largest incident: 2 alerts" in out
    assert "incidents above 50 alerts: 0" in out
    assert "lab_a: 2 -> 1" in out


def test_measure_needs_a_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert measure_correlation.main(["measure"]) == 2
