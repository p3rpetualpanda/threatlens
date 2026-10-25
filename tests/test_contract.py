from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from app.contract import FindingError, validate_findings

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "findings.jsonl"


def _fixture() -> list[dict[str, Any]]:
    return [json.loads(line) for line in FIXTURE.read_text("utf-8").splitlines()]


def test_vendored_schema_matches_recorded_hash() -> None:
    schema = ROOT / "contracts" / "detection-finding-v1.schema.json"
    recorded = (ROOT / "contracts" / "README.md").read_text("utf-8")
    assert hashlib.sha256(schema.read_bytes()).hexdigest() in recorded


def test_fixture_is_valid() -> None:
    items = _fixture()
    assert len(items) == 4
    assert validate_findings(list(items)) == []


def test_missing_required_field_reports_index_and_path() -> None:
    items = _fixture()
    broken = copy.deepcopy(items)
    del broken[2]["finding_info"]["uid"]
    errors = validate_findings(list(broken))
    assert [e.index for e in errors] == [2]
    assert "uid" in errors[0].message
    assert errors[0].path.startswith("finding_info")


def test_schema_version_major_2_rejected() -> None:
    broken = copy.deepcopy(_fixture())
    broken[0]["schema_version"] = "2.0"
    errors = validate_findings(list(broken))
    assert [e.index for e in errors] == [0]
    assert errors[0].path == "schema_version"


def test_non_object_item_rejected() -> None:
    items: list[object] = [*_fixture(), "not a finding", 7]
    assert [e.index for e in validate_findings(items)] == [4, 5]


def test_errors_are_ordered_by_index_and_typed() -> None:
    broken = copy.deepcopy(_fixture())
    broken[3]["severity_id"] = 9
    broken[1]["severity_id"] = 9
    errors = validate_findings(list(broken))
    assert [e.index for e in errors] == [1, 3]
    assert isinstance(errors[0], FindingError)
