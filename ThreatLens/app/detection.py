"""Explainable detections for the ThreatLens demonstration dataset."""

from collections import defaultdict
from datetime import timedelta
from typing import Dict, Iterable, List

from .models import Alert, Evidence, SecurityEvent


def _severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _alert(
    alert_id: str,
    title: str,
    technique_id: str,
    technique_name: str,
    confidence: float,
    events: List[SecurityEvent],
    explanations: List[str],
    recommendation: str,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        title=title,
        technique_id=technique_id,
        technique_name=technique_name,
        severity=_severity(confidence),
        confidence=confidence,
        first_seen=min(event.timestamp for event in events),
        last_seen=max(event.timestamp for event in events),
        evidence=[
            Evidence(event_id=event.event_id, explanation=explanation)
            for event, explanation in zip(events, explanations)
        ],
        recommendation=recommendation,
    )


def detect(events: Iterable[SecurityEvent]) -> List[Alert]:
    """Run deterministic, explainable rules over normalized security events."""
    events = list(events)
    alerts: List[Alert] = []

    failed_by_ip: Dict[str, List[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "authentication" and event.outcome == "failure":
            failed_by_ip[event.source_ip].append(event)
    for source_ip, failures in failed_by_ip.items():
        if len(failures) >= 5:
            selected = failures[:5]
            alerts.append(
                _alert(
                    "brute-force-" + source_ip.replace(".", "-"),
                    "Repeated authentication failures",
                    "T1110",
                    "Brute Force",
                    min(0.99, 0.70 + len(failures) * 0.04),
                    selected,
                    ["Failed login from " + source_ip] * len(selected),
                    "Block or rate-limit the source and verify the targeted account.",
                )
            )

    for event in events:
        if event.event_type == "process" and event.command:
            command = event.command.lower()
            if "powershell" in command and ("-enc" in command or "downloadstring" in command):
                alerts.append(
                    _alert(
                        "powershell-" + event.event_id,
                        "Encoded or remote PowerShell execution",
                        "T1059.001",
                        "PowerShell",
                        0.93,
                        [event],
                        ["Command contains an encoded or remote-download PowerShell indicator."],
                        "Isolate the host, capture process details, and review the parent process.",
                    )
                )

    for event in events:
        if event.event_type == "network" and event.bytes_sent >= 50000000:
            alerts.append(
                _alert(
                    "exfiltration-" + event.event_id,
                    "Unusually large outbound transfer",
                    "T1041",
                    "Exfiltration Over C2 Channel",
                    0.82,
                    [event],
                    ["Outbound transfer exceeded the 50 MB demonstration threshold."],
                    "Validate the destination and business purpose before blocking the connection.",
                )
            )

    auth_by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "authentication" and event.outcome == "success" and event.username:
            auth_by_user[event.username].append(event)
    for username, logins in auth_by_user.items():
        for first in logins:
            for second in logins:
                if first.event_id >= second.event_id:
                    continue
                if abs((second.timestamp - first.timestamp).total_seconds()) <= 3600 and first.source_ip != second.source_ip:
                    alerts.append(
                        _alert(
                            "impossible-travel-" + username,
                            "Successful logins from multiple locations",
                            "T1078",
                            "Valid Accounts",
                            0.76,
                            [first, second],
                            [
                                "Successful login from " + first.source_ip,
                                "Second successful login from " + second.source_ip + " within one hour.",
                            ],
                            "Confirm the user's location and revoke sessions if the activity is unauthorized.",
                        )
                    )
                    break
            else:
                continue
            break

    return alerts
