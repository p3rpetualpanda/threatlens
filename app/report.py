"""Incident report: one dict of facts, rendered as Markdown (file) or HTML (print page).

All text is built here from fixed templates plus stored values. Every stored value is escaped
for Markdown on the way into the .md file; the HTML page relies on Jinja2 autoescape.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from .incidents_api import get_incident
from .playbooks import PHASES
from .ui import _entities
from .workflow import incident_steps

_MD = re.compile(r"([\`*_{}\[\]()<>#+\-.!|~&])")
_AUDIT_SHOWN = 50


def md(value: object) -> str:
    """One line of plain text made safe inside Markdown: no markup, links or raw HTML."""
    text = " ".join(str(value).split())
    return _MD.sub(lambda m: "\\" + m.group(1), text)


def build(conn: sqlite3.Connection, incident_id: str) -> dict[str, Any] | None:
    """The report facts, or None for an unknown or merged-away incident."""
    inc = get_incident(incident_id)  # raises 404 itself
    if inc["merged_into"]:
        return None
    timeline = conn.execute(
        "SELECT a.time, a.rule, a.severity, a.technique FROM incident_alerts ia "
        "JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id = ? "
        "ORDER BY a.time, a.finding_info_uid",
        [incident_id],
    ).fetchall()
    audit = conn.execute(
        "SELECT at, actor, action FROM audit_log WHERE target = ? AND action LIKE 'incident.%' "
        "ORDER BY id LIMIT ?",
        [incident_id, _AUDIT_SHOWN],
    ).fetchall()
    steps = incident_steps(conn, incident_id)
    entities = _entities(conn, incident_id, inc["environment"])
    rules = sorted({a["rule"] for a in inc["alerts"]})
    risk = (
        "not scored" if inc["risk_score"] is None else f"{inc['risk_score']} ({inc['risk_label']})"
    )
    summary = (
        f"This incident groups {inc['alert_count']} alert(s) from {len(rules)} rule(s) in "
        f"environment {inc['environment']}, first seen {inc['first_seen']} and last seen "
        f"{inc['last_seen']}. Its risk score is {risk}. Its status is {inc['status']} and its "
        f"disposition is {inc['disposition'] or 'not set'}."
    )
    return {
        "inc": inc,
        "summary": summary,
        "entities": entities,
        "timeline": [dict(r) for r in timeline],
        "actions": [dict(r) for r in audit],
        "phases": [
            {
                "phase": p,
                "steps": [{"action": s.action, "done": d} for s, d in steps if s.phase == p],
            }
            for p in PHASES
            if any(s.phase == p for s, _ in steps)
        ],
    }


def to_markdown(r: dict[str, Any]) -> str:
    inc = r["inc"]
    out = [f"# Incident report: {md(inc['title'])}", "", "## Summary", "", md(r["summary"]), ""]
    out += ["## Scope", ""]
    out += [
        f"- Environment: {md(inc['environment'])}",
        f"- Owner: {md(inc['owner_email'] or 'unassigned')}",
    ]
    out += [f"- Alerts: {inc['alert_count']}"]
    out += [f"- {md(e['kind'])}: {md(e['value'])}" for e in r["entities"]]
    out += [""]
    out += ["## Timeline", ""]
    for t in r["timeline"]:
        tech = f" {md(t['technique'])}" if t["technique"] else ""
        out.append(f"- {md(t['time'] or 'no time')} {md(t['rule'])} ({md(t['severity'])}){tech}")
    out += ["", "## ATT&CK techniques", ""]
    out += [
        f"- {md(t['id'])} {md(t['name'])}: {md(', '.join(t['tactics']))}" for t in inc["techniques"]
    ]
    out += ["", "## Risk factors", ""]
    out += [
        f"- +{int(f['points'])} {md(f['factor'])}: {md(f['reason'])}" for f in inc["risk_factors"]
    ]
    out += ["", "## Response checklist", ""]
    for ph in r["phases"]:
        out.append(f"### {md(ph['phase'].replace('_', ' ').capitalize())}")
        out.append("")
        out += [f"- [{'x' if s['done'] else ' '}] {md(s['action'])}" for s in ph["steps"]]
        out.append("")
    out += ["## Actions taken", ""]
    out += [f"- {md(a['at'])} {md(a['actor'])}: {md(a['action'])}" for a in r["actions"]]
    out += ["", "## Disposition", "", md(inc["disposition"] or "not set"), ""]
    return "\n".join(out).rstrip() + "\n"
