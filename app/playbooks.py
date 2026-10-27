"""Response playbooks (spec 6.6): config/playbooks/*.yml, phases from NIST SP 800-61.

A playbook claims techniques and/or tactics in `applies_to`. Lookup for one technique: exact id,
then its parent technique, then its tactics, then default.yml. An incident shows the merged,
de-duplicated checklist of all its techniques. A step id is `<playbook id>.<position>`, so
reordering a playbook after analysts ticked steps orphans their ticks.
shortcut: step ids follow position; give steps explicit ids if playbooks start being edited often.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from . import attack

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "config" / "playbooks"
PHASES = ("containment", "eradication", "recovery", "lessons_learned")
_STEP_KEYS = {"phase", "action", "d3fend", "evidence_hint"}
_TOP_KEYS = {"id", "title", "applies_to", "steps"}


class PlaybookError(Exception):
    pass


@dataclass(frozen=True)
class Step:
    id: str
    playbook: str
    phase: str
    action: str
    d3fend: str | None = None
    evidence_hint: str | None = None


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    applies_to: tuple[str, ...]
    steps: tuple[Step, ...]


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlaybookError(f"{where}: must be a non-empty string")
    return value.strip()


def _parse(path: Path, d3fend: set[str]) -> Playbook:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) - _TOP_KEYS or "id" not in raw:
        raise PlaybookError(f"{path.name}: expected a mapping with {sorted(_TOP_KEYS)}")
    pid = _text(raw["id"], f"{path.name} id")
    applies = raw.get("applies_to") or []
    if not isinstance(applies, list) or not all(isinstance(a, str) and a for a in applies):
        raise PlaybookError(f"{path.name}: applies_to must be a list of strings")
    items = raw.get("steps")
    if not isinstance(items, list) or not items:
        raise PlaybookError(f"{path.name}: needs at least one step")
    steps = []
    for n, item in enumerate(items, 1):
        where = f"{path.name} step {n}"
        if not isinstance(item, dict) or set(item) - _STEP_KEYS:
            raise PlaybookError(f"{where}: unknown or missing fields")
        if item.get("phase") not in PHASES:
            raise PlaybookError(f"{where}: phase must be one of {', '.join(PHASES)}")
        mapped = item.get("d3fend")
        if mapped is not None and mapped not in d3fend:
            raise PlaybookError(f"{where}: {mapped} is not in the pinned D3FEND list")
        hint = item.get("evidence_hint")
        steps.append(
            Step(
                f"{pid}.{n}",
                pid,
                item["phase"],
                _text(item.get("action"), f"{where} action"),
                mapped,
                None if hint is None else _text(hint, f"{where} evidence_hint"),
            )
        )
    return Playbook(
        pid, _text(raw.get("title"), f"{path.name} title"), tuple(applies), tuple(steps)
    )


def load_playbooks(folder: Path | None = None) -> dict[str, Playbook]:
    folder = folder or DEFAULT_DIR
    pinned = {
        line.split()[0]
        for line in (folder / "d3fend.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    found: dict[str, Playbook] = {}
    claimed: dict[str, str] = {}
    for path in sorted(folder.glob("*.yml")):
        pb = _parse(path, pinned)
        if pb.id in found:
            raise PlaybookError(f"{path.name}: duplicate playbook id {pb.id}")
        for key in pb.applies_to:
            if key in claimed:
                raise PlaybookError(f"{key} is claimed by both {claimed[key]} and {pb.id}")
            claimed[key] = pb.id
        found[pb.id] = pb
    if "default" not in found:
        raise PlaybookError("default.yml is required")
    return found


@lru_cache(maxsize=1)
def shipped() -> dict[str, Playbook]:
    return load_playbooks()


def _pick(technique: str, tactics: list[str], playbooks: dict[str, Playbook]) -> Playbook:
    by_key = {key: pb for pb in playbooks.values() for key in pb.applies_to}
    for key in (technique, technique.split(".")[0], *tactics):
        if key in by_key:
            return by_key[key]
    return playbooks["default"]


def steps_for(
    techniques: list[str],
    playbooks: dict[str, Playbook] | None = None,
    tactics: dict[str, list[str]] | None = None,
) -> list[Step]:
    """The merged checklist for these techniques, in phase order, repeats removed."""
    playbooks = playbooks or shipped()
    chosen: dict[str, Playbook] = {}
    for tid in sorted(techniques) or [""]:
        known = tactics[tid] if tactics and tid in tactics else attack.describe(tid)["tactics"]
        pb = _pick(tid, list(known), playbooks)
        chosen.setdefault(pb.id, pb)
    seen: set[tuple[str, str]] = set()
    merged: list[Step] = []
    for pb in chosen.values():
        for step in pb.steps:
            if (step.phase, step.action) not in seen:
                seen.add((step.phase, step.action))
                merged.append(step)
    return sorted(merged, key=lambda s: PHASES.index(s.phase))  # stable: keeps file order
