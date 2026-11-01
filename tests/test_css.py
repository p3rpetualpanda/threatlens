"""Touch targets: WCAG 2.2 AA 2.5.8 wants every control and standalone link at least 24 CSS px."""

from __future__ import annotations

import re
from pathlib import Path

CSS = (Path(__file__).resolve().parent.parent / "app" / "static" / "app.css").read_text("utf-8")
MIN_REM = 1.5  # 24 px at the 16 px base


def _body(selector: str) -> str:
    """The declarations of a rule that starts its own line and ends with `}` on that line."""
    rule = re.search(rf"(?m)^{re.escape(selector)}\s*\{{([^}}]*)\}}\s*(?:/\*.*\*/)?$", CSS)
    assert rule, f"no rule for {selector} (or something else shares its line)"
    return rule.group(1)


def _rem(selector: str, prop: str) -> float:
    value = re.search(rf"{prop}:\s*([\d.]+)rem", _body(selector))
    assert value, f"{selector} sets no {prop} in rem"
    return float(value.group(1))


def test_checkboxes_are_at_least_24px() -> None:
    sel = "input[type=checkbox]"
    assert _rem(sel, "width") >= MIN_REM and _rem(sel, "height") >= MIN_REM


def test_links_in_main_are_at_least_24px_tall() -> None:
    assert _rem("main a", "min-height") >= MIN_REM
    assert "display: inline-block" in _body("main a")  # min-height is ignored on inline boxes


def test_buttons_are_at_least_24px_tall() -> None:
    assert _rem("button", "min-height") >= MIN_REM


def test_fieldset_rule_has_its_own_line() -> None:
    assert "min-width: 0" in _body("fieldset")
