from __future__ import annotations

import sys
from contextlib import closing
from pathlib import Path

import pytest

from app.db import connect

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import seed_demo

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "findings.jsonl"


def _counts(db: Path) -> tuple[int, int, int]:
    with closing(connect(db)) as conn:
        a, u, s = (
            conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608
            for t in ("alerts", "users", "assets")
        )
    return a, u, s


def test_seed_loads_data_and_prints_a_login_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "t.db"
    assert seed_demo.main([str(db), str(FIXTURE), str(ROOT / "config")]) == 0
    out = capsys.readouterr().out
    alerts, users, assets = _counts(db)
    assert alerts == 4 and users == 1 and assets > 0
    assert "demo@example.test" in out and "password:" in out
    first = out

    # a restart must not add data, make a second admin or print a new password
    assert seed_demo.main([str(db), str(FIXTURE), str(ROOT / "config")]) == 0
    assert _counts(db) == (alerts, users, assets)
    assert "password:" not in capsys.readouterr().out
    assert first.count("password:") == 1
