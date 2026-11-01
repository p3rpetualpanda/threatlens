"""Manual round trip: fixture findings -> dispositions -> verdicts CSV -> beacon -> precision.

    uv run python scripts/roundtrip_beacon.py ../../beacon

Needs a beacon checkout (its own env supplies duckdb). Dispositions are written straight to the
alerts table, as the resolve cascade would. Prints each rule's precision before and after.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from app import cli

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "findings.jsonl"
# alert uid -> disposition: R05 true, R01 false, R20 benign, R09 left undecided
PLAN = {
    "f0000000000000000000000000000001": "true_positive",
    "f0000000000000000000000000000002": "false_positive",
    "f0000000000000000000000000000003": "benign_true_positive",
}

BEACON_SIDE = """
import json, sys
from pathlib import Path
from beacon import db
from beacon.detect import apply_verdicts

findings = [json.loads(x) for x in Path(sys.argv[2]).read_text("utf-8").splitlines()]
con = db.connect(":memory:")
con.execute("INSERT INTO datasets VALUES ('fixture', '', '', '', '', "
            "['T1059.001', 'T1110', 'T1547.001'])")
for f in findings:
    info = f["finding_info"]
    rule, tech = info["analytic"]["uid"], info["attacks"][0]["technique"]["uid"]
    con.execute("INSERT OR IGNORE INTO rules VALUES (?, ?, ?, 'x', 'medium', '')",
                [rule, rule, tech])
    con.execute("INSERT INTO alerts (alert_id, rule_id, ts, dataset, summary, event_ids) "
                "VALUES (?, ?, now(), 'fixture', 's', [])", [info["uid"], rule])
q = "SELECT rule_id, precision, verdicts FROM rule_performance ORDER BY rule_id"
print("before", con.execute(q).fetchall())
print("applied, missing, conflicts:", apply_verdicts(con, Path(sys.argv[1])))
print("after ", con.execute(q).fetchall())
"""


def main(beacon: Path) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        db, out = Path(tmp) / "t.db", Path(tmp) / "verdicts.csv"
        if cli.main(["import", str(FIXTURE), "--db", str(db)]) != 0:
            return 1
        with closing(sqlite3.connect(db)) as conn:
            for uid, disposition in PLAN.items():
                conn.execute(
                    "UPDATE alerts SET disposition = ? WHERE finding_info_uid = ?",
                    [disposition, uid],
                )
            conn.commit()
        if cli.main(["export-verdicts", "--out", str(out), "--db", str(db)]) != 0:
            return 1
        print(out.read_text("utf-8"))
        cmd = ["uv", "run", "--project", str(beacon), "python", "-I", "-c", BEACON_SIDE]
        return subprocess.run([*cmd, str(out), str(FIXTURE)], check=False).returncode  # noqa: S603


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
