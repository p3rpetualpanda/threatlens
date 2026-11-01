"""Analyst dispositions as a beacon verdicts file (spec 6.7 item 7).

Beacon's `read_verdicts` takes `alert_id,status,reason` and refuses the status `new`, so only
alerts with a disposition can be exported. The reason is built from ids, never from user text.
Beacon's own ids are hex hashes, so the formula guard only ever changes a hostile uid (which then
matches nothing in beacon and is reported as missing).
"""

from __future__ import annotations

import sqlite3

_FORMULA_STARTS = ("=", "+", "-", "@", chr(9), chr(13))
FIELDS = ["alert_id", "status", "reason"]
# benign true positives are real but harmless: beacon's `closed` keeps them out of precision
_STATUS = {
    "true_positive": "true_positive",
    "false_positive": "false_positive",
    "benign_true_positive": "closed",
}


def build_rows(conn: sqlite3.Connection) -> list[tuple[str, str, str]]:
    rows = []
    for r in conn.execute(
        "SELECT a.finding_info_uid, a.disposition, "
        "(SELECT MIN(ia.incident_id) FROM incident_alerts ia "
        "JOIN incidents i ON i.id = ia.incident_id "
        "WHERE ia.alert_id = a.id AND i.merged_into IS NULL) AS incident "
        "FROM alerts a WHERE a.disposition IS NOT NULL ORDER BY a.finding_info_uid"
    ):
        reason = f"threatlens incident {r['incident']}" if r["incident"] else "threatlens"
        if r["disposition"] == "benign_true_positive":
            reason = f"benign: {reason}"
        uid = r["finding_info_uid"]
        if uid.startswith(_FORMULA_STARTS):  # a spreadsheet would run it as a formula
            uid = "'" + uid
        rows.append((uid, _STATUS[r["disposition"]], reason))
    return rows
