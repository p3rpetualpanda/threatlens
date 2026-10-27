"""Incident risk score: points per factor, each with its reason (spec 6.5). Pure, no database.

The score is the sum of the factor points, capped at 100 by a final negative ``cap`` factor, so
the stored factors always add up to the stored score.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "risk.yml"
_KEYS = {
    "severity_points",
    "extra_tactic_points",
    "progress_tactics",
    "progress_points",
    "criticality_points",
    "privileged_points",
    "auth_tactics",
    "public_ip_points",
    "label_floors",
}


@dataclass(frozen=True)
class RiskConfig:
    severity_points: dict[str, int]
    extra_tactic_points: int
    progress_tactics: frozenset[str]
    progress_points: int
    criticality_points: dict[int, int]
    privileged_points: int
    auth_tactics: frozenset[str]
    public_ip_points: int
    label_floors: dict[str, int]


def load_risk_config(path: Path | None = None) -> RiskConfig:
    raw = yaml.safe_load((path or DEFAULT_PATH).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("risk config must be a mapping")
    if raw.keys() != _KEYS:
        raise ValueError(f"risk config keys differ: {sorted(raw.keys() ^ _KEYS)}")
    return RiskConfig(
        severity_points={str(k): int(v) for k, v in raw["severity_points"].items()},
        extra_tactic_points=int(raw["extra_tactic_points"]),
        progress_tactics=frozenset(str(t) for t in raw["progress_tactics"]),
        progress_points=int(raw["progress_points"]),
        criticality_points={int(k): int(v) for k, v in raw["criticality_points"].items()},
        privileged_points=int(raw["privileged_points"]),
        auth_tactics=frozenset(str(t) for t in raw["auth_tactics"]),
        public_ip_points=int(raw["public_ip_points"]),
        label_floors={str(k): int(v) for k, v in raw["label_floors"].items()},
    )


def score(
    severities: list[str],
    tactics: set[str],
    cfg: RiskConfig,
    criticality: int | None = None,
    privileged: list[str] | None = None,
    public_ips: list[str] | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Return (score 0-100, factors as {factor, points, reason}).

    ``criticality`` is the highest asset criticality among the incident's hosts, ``privileged``
    the privileged identities involved, ``public_ips`` the public source IPs seen in
    authentication alerts.
    """
    factors: list[dict[str, Any]] = []
    known = [s for s in severities if s in cfg.severity_points]
    if known:
        top = max(known, key=lambda s: cfg.severity_points[s])
        factors.append(
            {
                "factor": "severity",
                "points": cfg.severity_points[top],
                "reason": f"highest alert severity is {top}",
            }
        )
    if len(tactics) > 1:
        extra = len(tactics) - 1
        factors.append(
            {
                "factor": "tactics",
                "points": cfg.extra_tactic_points * extra,
                "reason": f"{len(tactics)} distinct ATT&CK tactics ({extra} beyond the first)",
            }
        )
    hit = sorted(tactics & cfg.progress_tactics)
    if hit:
        factors.append(
            {
                "factor": "progress",
                "points": cfg.progress_points,
                "reason": f"{' and '.join(hit)} present",
            }
        )
    if criticality and cfg.criticality_points.get(criticality):
        factors.append(
            {
                "factor": "asset",
                "points": cfg.criticality_points[criticality],
                "reason": f"involves an asset of criticality {criticality}",
            }
        )
    if privileged:
        factors.append(
            {
                "factor": "privileged",
                "points": cfg.privileged_points,
                "reason": f"privileged identity involved: {', '.join(sorted(privileged)[:3])}",
            }
        )
    if public_ips:
        factors.append(
            {
                "factor": "public_ip",
                "points": cfg.public_ip_points,
                "reason": "public source IP in an authentication alert: "
                + ", ".join(sorted(public_ips)[:3]),
            }
        )
    total = sum(f["points"] for f in factors)
    if total > 100:
        factors.append({"factor": "cap", "points": 100 - total, "reason": "score is capped at 100"})
        total = 100
    return total, factors


def label(value: int, cfg: RiskConfig) -> str:
    """Severity label for a score: the highest floor reached, else Low."""
    best = "Low"
    best_floor = -1
    for name, floor in cfg.label_floors.items():
        if best_floor < floor <= value:
            best, best_floor = name, floor
    return best
