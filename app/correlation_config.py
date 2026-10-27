"""Correlation settings, loaded from config/correlation.yml (spec 6.4)."""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "correlation.yml"
_KEYS = {
    "link_window_minutes",
    "ignored_users",
    "ignore_machine_accounts",
    "auto_share",
    "auto_min_alerts",
}


@dataclass(frozen=True)
class CorrelationConfig:
    link_window: timedelta
    ignored_users: frozenset[str]
    ignore_machine_accounts: bool
    auto_share: float
    auto_min_alerts: int


def load_config(path: Path | None = None) -> CorrelationConfig:
    raw = yaml.safe_load((path or DEFAULT_PATH).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("correlation config must be a mapping")
    if raw.keys() != _KEYS:
        raise ValueError(f"correlation config keys differ: {sorted(raw.keys() ^ _KEYS)}")
    return CorrelationConfig(
        link_window=timedelta(minutes=int(raw["link_window_minutes"])),
        ignored_users=frozenset(str(u).lower() for u in raw["ignored_users"]),
        ignore_machine_accounts=bool(raw["ignore_machine_accounts"]),
        auto_share=float(raw["auto_share"]),
        auto_min_alerts=int(raw["auto_min_alerts"]),
    )
