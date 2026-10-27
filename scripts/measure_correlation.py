"""Print how well correlation reduced a database's alerts into incidents (read-only).

Usage: python scripts/measure_correlation.py path/to/threatlens.db
"""

from __future__ import annotations

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from app.db import connect

LIMIT = 50  # acceptance: no incident above this many alerts unless justified


def measure(db_path: Path) -> list[str]:
    with closing(connect(db_path)) as conn:
        alerts = _one(conn, "SELECT count(*) FROM alerts")
        sizes = conn.execute(
            "SELECT i.environment AS env, i.id, i.title, count(ia.alert_id) AS n "
            "FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id "
            "WHERE i.merged_into IS NULL GROUP BY i.id ORDER BY n DESC, i.id"
        ).fetchall()
        per_env = conn.execute(
            "SELECT a.environment AS env, count(DISTINCT a.id) AS alerts, "
            "count(DISTINCT ia.incident_id) AS incidents FROM alerts a "
            "LEFT JOIN incident_alerts ia ON ia.alert_id = a.id GROUP BY a.environment "
            "ORDER BY a.environment"
        ).fetchall()
    incidents = len(sizes)
    lines = [f"alerts: {alerts}", f"incidents: {incidents}"]
    if incidents:
        lines.append(f"reduction: {alerts / incidents:.1f} alerts per incident")
        top = sizes[0]
        lines.append(f"largest incident: {top['n']} alerts ({top['env']}: {top['title']})")
        over = [s for s in sizes if s["n"] > LIMIT]
        lines.append(f"incidents above {LIMIT} alerts: {len(over)}")
        lines.append(f"single-alert incidents: {sum(s['n'] == 1 for s in sizes)}")
    lines.append("per environment (alerts -> incidents):")
    lines += [f"  {r['env']}: {r['alerts']} -> {r['incidents']}" for r in per_env]
    return lines


def _one(conn: sqlite3.Connection, sql: str) -> int:
    return int(conn.execute(sql).fetchone()[0])


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    print("\n".join(measure(Path(argv[1]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
