"""Offline ATT&CK names for technique ids, from app/data/attack_subset.json (spec 6.5)."""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SUBSET = Path(__file__).resolve().parent / "data" / "attack_subset.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SUBSET.read_text(encoding="utf-8"))
    return data


def version() -> str:
    return str(_load()["version"])


def describe(technique_id: str) -> dict[str, Any]:
    """Name, tactics and url for an id; an id not in the subset is named "Unknown"."""
    known = _load()["techniques"].get(technique_id)
    if known is None:
        return {"id": technique_id, "name": "Unknown", "tactics": [], "url": ""}
    return {"id": technique_id, **known}
