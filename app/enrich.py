"""Offline enrichment: IP class, and assets / identities loaded from CSV (spec 6.5)."""

from __future__ import annotations

import csv
import ipaddress
import sqlite3
from datetime import datetime
from pathlib import Path

from .audit import record

_DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_ASSET_COLUMNS = ["environment", "host", "criticality", "owner", "role"]
_IDENTITY_COLUMNS = ["environment", "user", "privileged", "department"]
_SQL = {
    "assets": ("DELETE FROM assets", "INSERT INTO assets VALUES (?, ?, ?, ?, ?)"),
    "identities": ("DELETE FROM identities", "INSERT INTO identities VALUES (?, ?, ?, ?)"),
}
_BOOLS = {"true": 1, "yes": 1, "1": 1, "false": 0, "no": 0, "0": 0}


def ip_class(value: str) -> str:
    """documentation | loopback | private | public | unknown. No lookups."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return "unknown"
    if any(ip in net for net in _DOC_NETS):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return "private"
    return "public"


def _rows(path: Path, columns: list[str]) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    if reader.fieldnames != columns:
        raise ValueError(f"{path}: header must be {','.join(columns)}")
    rows = list(reader)
    if not rows:  # an empty file must never wipe the table
        raise ValueError(f"{path}: no rows")
    return rows


def _load(
    conn: sqlite3.Connection,
    path: Path,
    columns: list[str],
    table: str,
    key: str,
    now: datetime,
) -> int:
    """Replace the whole table from the CSV, in one transaction."""
    rows = _rows(path, columns)
    out: list[tuple[object, ...]] = []
    seen: set[tuple[str, str]] = set()
    for n, r in enumerate(rows, start=2):
        env, name = (r["environment"] or "").strip(), (r[key] or "").strip().lower()
        if not env or not name:
            raise ValueError(f"{path} row {n}: environment and {key} are required")
        if (env, name) in seen:
            raise ValueError(f"{path} row {n}: duplicate {env}/{name}")
        seen.add((env, name))
        if table == "assets":
            if r["criticality"] not in ("1", "2", "3"):
                raise ValueError(f"{path} row {n}: criticality must be 1, 2 or 3")
            out.append((env, name, int(r["criticality"]), r["owner"].strip(), r["role"].strip()))
        else:
            flag = _BOOLS.get(r["privileged"].strip().lower())
            if flag is None:
                raise ValueError(f"{path} row {n}: privileged must be true or false")
            out.append((env, name, flag, r["department"].strip()))
    delete, insert = _SQL[table]
    with conn:
        conn.execute(delete)
        conn.executemany(insert, out)
        record(conn, "cli", f"{table}.load", None, {"rows": len(out)}, now)
    return len(out)


def load_assets(conn: sqlite3.Connection, path: Path, now: datetime) -> int:
    return _load(conn, path, _ASSET_COLUMNS, "assets", "host", now)


def load_identities(conn: sqlite3.Connection, path: Path, now: datetime) -> int:
    return _load(conn, path, _IDENTITY_COLUMNS, "identities", "user", now)
