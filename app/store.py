import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from .data import seed_events
from .detection import detect
from .models import Alert, AlertUpdate, Evidence, SecurityEvent


DatabasePath = Union[str, Path]


class SQLiteStore:
    def __init__(self, db_path: DatabasePath) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        username TEXT,
                        host TEXT,
                        action TEXT,
                        outcome TEXT,
                        command TEXT,
                        bytes_sent INTEGER NOT NULL,
                        metadata TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        technique_id TEXT NOT NULL,
                        technique_name TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        status TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        recommendation TEXT NOT NULL
                    );
                    """
                )
                event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if event_count == 0:
                    events = seed_events()
                    self._insert_events(connection, events)
                    self._recompute_alerts(connection)

    def _insert_events(
        self, connection: sqlite3.Connection, events: List[SecurityEvent]
    ) -> None:
        connection.executemany(
            """
            INSERT INTO events (
                event_id, timestamp, event_type, source_ip, username, host,
                action, outcome, command, bytes_sent, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.source_ip,
                    event.username,
                    event.host,
                    event.action,
                    event.outcome,
                    event.command,
                    event.bytes_sent,
                    json.dumps(event.metadata),
                )
                for event in events
            ],
        )

    def _load_events(self, connection: sqlite3.Connection) -> List[SecurityEvent]:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY timestamp, event_id"
        ).fetchall()
        return [
            SecurityEvent(
                event_id=row["event_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                event_type=row["event_type"],
                source_ip=row["source_ip"],
                username=row["username"],
                host=row["host"],
                action=row["action"],
                outcome=row["outcome"],
                command=row["command"],
                bytes_sent=row["bytes_sent"],
                metadata=json.loads(row["metadata"]),
            )
            for row in rows
        ]

    def _recompute_alerts(self, connection: sqlite3.Connection) -> None:
        existing_statuses = {
            row["alert_id"]: row["status"]
            for row in connection.execute("SELECT alert_id, status FROM alerts")
        }
        alerts = detect(self._load_events(connection))
        connection.execute("DELETE FROM alerts")
        connection.executemany(
            """
            INSERT INTO alerts (
                alert_id, title, technique_id, technique_name, severity,
                confidence, status, first_seen, last_seen, evidence, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    alert.alert_id,
                    alert.title,
                    alert.technique_id,
                    alert.technique_name,
                    alert.severity,
                    alert.confidence,
                    existing_statuses.get(alert.alert_id, alert.status),
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                    json.dumps([evidence.model_dump() for evidence in alert.evidence]),
                    alert.recommendation,
                )
                for alert in alerts
            ],
        )

    @staticmethod
    def _alert_from_row(row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            title=row["title"],
            technique_id=row["technique_id"],
            technique_name=row["technique_name"],
            severity=row["severity"],
            confidence=row["confidence"],
            status=row["status"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            evidence=[Evidence(**item) for item in json.loads(row["evidence"])],
            recommendation=row["recommendation"],
        )

    def list_alerts(self) -> List[Alert]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY last_seen DESC"
            ).fetchall()
        return [self._alert_from_row(row) for row in rows]

    def get_alert(self, alert_id: str) -> Alert:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
        if row is None:
            raise KeyError(alert_id)
        return self._alert_from_row(row)

    def update_alert(self, alert_id: str, update: AlertUpdate) -> Alert:
        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    "UPDATE alerts SET status = ? WHERE alert_id = ?",
                    (update.status, alert_id),
                )
                if result.rowcount == 0:
                    raise KeyError(alert_id)
        return self.get_alert(alert_id)

    def add_event(self, event: SecurityEvent) -> List[Alert]:
        try:
            with closing(self._connect()) as connection:
                with connection:
                    self._insert_events(connection, [event])
                    self._recompute_alerts(connection)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Event ID already exists") from exc
        return self.list_alerts()
