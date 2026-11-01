"""Print the correlation numbers for the README from a findings file, on a throwaway database.

Usage: readme_numbers.py [FINDINGS]   (default demo/beacon_findings.jsonl)
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from measure_correlation import measure

from app.cli import main as threatlens

DEMO = Path(__file__).resolve().parent.parent / "demo" / "beacon_findings.jsonl"


def main(argv: Sequence[str]) -> int:
    findings = Path(argv[0]) if argv else DEMO
    with TemporaryDirectory() as tmp:
        db = Path(tmp) / "numbers.db"
        if threatlens(["import", str(findings), "--db", str(db)]) != 0:
            return 1
        print("\n".join(measure(db)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
