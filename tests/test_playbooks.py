"""Playbooks: lookup order, merging, the pinned D3FEND list, and that every technique resolves."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import attack
from app.playbooks import PHASES, PlaybookError, load_playbooks, steps_for

# Every technique beacon's rules and the demo fixture can emit (T1070.001 is not in the pinned
# ATT&CK subset, so it is left out: an id the subset does not know is shown as Unknown).
BEACON_TECHNIQUES = [
    "T1003", "T1003.001", "T1021.002", "T1021.003", "T1021.006", "T1036.002", "T1047",
    "T1053.005", "T1057", "T1059.001", "T1070.004", "T1071.001", "T1082", "T1087.002",
    "T1110.001", "T1110.003", "T1113", "T1135", "T1136.001", "T1204.002", "T1543.003",
    "T1546.003", "T1547.001", "T1548.002", "T1550.003", "T1558.001", "T1558.003", "T1560.001",
    "T1569.002",
]  # fmt: skip


def _write(folder: Path, name: str, body: str) -> None:
    (folder / name).write_text(body, encoding="utf-8")


GOOD = """
id: {id}
title: {id} playbook
applies_to: {applies}
steps:
  - {{phase: containment, action: Do {id} first}}
"""


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    _write(tmp_path, "d3fend.txt", "D3-MFA Multi-factor Authentication\n")
    _write(tmp_path, "default.yml", GOOD.format(id="default", applies="[]"))
    return tmp_path


def test_every_beacon_technique_resolves_to_a_real_playbook() -> None:
    pbs = load_playbooks()
    for tid in BEACON_TECHNIQUES:
        found = steps_for([tid], pbs)
        assert found, tid
        assert {s.playbook for s in found} != {"default"}, f"{tid} falls through to default"
        assert attack.describe(tid)["name"] != "Unknown", tid


def test_unknown_technique_and_no_technique_get_the_default() -> None:
    pbs = load_playbooks()
    assert {s.playbook for s in steps_for(["T9999"], pbs)} == {"default"}
    assert {s.playbook for s in steps_for([], pbs)} == {"default"}


def test_lookup_order_is_exact_then_parent_then_tactic_then_default(folder: Path) -> None:
    _write(folder, "a.yml", GOOD.format(id="exact", applies="[T1110.001]"))
    _write(folder, "b.yml", GOOD.format(id="parent", applies="[T1110]"))
    _write(folder, "c.yml", GOOD.format(id="tactic", applies="[Credential Access]"))
    pbs = load_playbooks(folder)

    def pick(t: str, tactics: list[str]) -> str:
        return steps_for([t], pbs, {t: tactics})[0].playbook

    assert pick("T1110.001", ["Credential Access"]) == "exact"
    assert pick("T1110.003", ["Credential Access"]) == "parent"
    assert pick("T1003", ["Credential Access"]) == "tactic"
    assert pick("T1059", ["Execution"]) == "default"


def test_steps_merge_dedupe_and_follow_the_phase_order(folder: Path) -> None:
    _write(
        folder,
        "a.yml",
        "id: a\ntitle: a\napplies_to: [T1]\nsteps:\n"
        "  - {phase: recovery, action: Restore}\n  - {phase: containment, action: Isolate}\n",
    )
    _write(
        folder,
        "b.yml",
        "id: b\ntitle: b\napplies_to: [T2]\nsteps:\n"
        "  - {phase: containment, action: Isolate}\n  - {phase: eradication, action: Remove}\n",
    )
    merged = steps_for(["T1", "T2"], load_playbooks(folder))
    assert [(s.phase, s.action) for s in merged] == [
        ("containment", "Isolate"),
        ("eradication", "Remove"),
        ("recovery", "Restore"),
    ]
    assert len({s.id for s in merged}) == 3


def test_step_ids_are_stable_and_unique() -> None:
    pbs = load_playbooks()
    ids = [s.id for p in pbs.values() for s in p.steps]
    assert len(ids) == len(set(ids))
    assert [s.id for s in steps_for(["T1110.001"], pbs)] == [
        s.id for s in steps_for(["T1110.001"], pbs)
    ]


@pytest.mark.parametrize(
    "body",
    [
        "id: x\ntitle: t\napplies_to: [T1]\nsteps: []\n",  # no steps
        "id: x\ntitle: t\napplies_to: [T1]\nsteps:\n  - {phase: panic, action: a}\n",
        "id: x\ntitle: t\napplies_to: [T1]\nsteps:\n  - {phase: recovery, action: ''}\n",
        "id: x\ntitle: t\napplies_to: [T1]\nsteps:\n"
        "  - {phase: recovery, action: a, d3fend: D3-NOPE}\n",
        "id: x\ntitle: t\napplies_to: [T1]\nsteps:\n  - {phase: recovery, action: a, extra: 1}\n",
        "- not a mapping\n",
    ],
)
def test_a_bad_playbook_fails_loudly(folder: Path, body: str) -> None:
    _write(folder, "bad.yml", body)
    with pytest.raises(PlaybookError):
        load_playbooks(folder)


def test_two_playbooks_may_not_claim_the_same_key(folder: Path) -> None:
    _write(folder, "a.yml", GOOD.format(id="a", applies="[T1]"))
    _write(folder, "b.yml", GOOD.format(id="b", applies="[T1]"))
    with pytest.raises(PlaybookError):
        load_playbooks(folder)


def test_a_known_d3fend_id_is_accepted(folder: Path) -> None:
    _write(
        folder,
        "a.yml",
        "id: a\ntitle: a\napplies_to: [T1]\nsteps:\n"
        "  - {phase: containment, action: Enforce MFA, d3fend: D3-MFA}\n",
    )
    assert load_playbooks(folder)["a"].steps[0].d3fend == "D3-MFA"


def test_the_shipped_playbooks_only_use_pinned_phases() -> None:
    for p in load_playbooks().values():
        assert {s.phase for s in p.steps} <= set(PHASES)
