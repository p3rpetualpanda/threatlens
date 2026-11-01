from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import readme_numbers

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "findings.jsonl"


def test_numbers_come_from_a_fresh_import(capsys: pytest.CaptureFixture[str]) -> None:
    assert readme_numbers.main([str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "alerts: 4" in out and "incidents: 3" in out
