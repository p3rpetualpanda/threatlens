from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

_SCHEMA = Path(__file__).resolve().parent.parent / "contracts" / "detection-finding-v1.schema.json"
_MAX_EPOCH_MS = 253_402_300_799_999  # 9999-12-31T23:59:59.999Z


def _short(message: str) -> str:
    # jsonschema messages echo the offending value; cap them so a big value is not sent back.
    return message if len(message) <= 200 else message[:200] + "..."


@dataclass(frozen=True)
class FindingError:
    index: int
    path: str
    message: str


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema: dict[str, Any] = json.loads(_SCHEMA.read_text("utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_findings(findings: list[object]) -> list[FindingError]:
    """Check each item against the vendored beacon contract; empty list means all valid.

    The schema's `schema_version` pattern (`^1\\.\\d+$`) is what enforces major version 1.
    """
    validator = _validator()
    errors = []
    for index, item in enumerate(findings):
        for err in sorted(validator.iter_errors(item), key=lambda e: list(e.absolute_path)):
            path = ".".join(str(p) for p in err.absolute_path)
            errors.append(FindingError(index, path, _short(err.message)))
        # The schema allows any integer; ingest turns `time` into a date, which stops at 9999.
        time = item.get("time") if isinstance(item, dict) else None
        # JSON 1e19 is a float that the schema's `integer` also accepts.
        if isinstance(time, int | float) and time > _MAX_EPOCH_MS:
            errors.append(FindingError(index, "time", f"{time} is beyond year 9999"))
    return errors
