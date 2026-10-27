from pathlib import Path

import pytest

from app.risk import RiskConfig, label, load_risk_config, score

CFG = load_risk_config()


def test_defaults_match_the_spec() -> None:
    assert CFG.severity_points == {"Low": 10, "Medium": 20, "High": 35, "Critical": 50}
    assert (CFG.extra_tactic_points, CFG.progress_points) == (8, 10)


def test_rejects_unknown_key(tmp_path: Path) -> None:
    p = tmp_path / "r.yml"
    p.write_text("bogus: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bogus"):
        load_risk_config(p)


def test_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "r.yml"
    p.write_text("- 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_risk_config(p)


def test_single_alert_has_only_a_severity_factor() -> None:
    total, factors = score(["Medium"], {"Execution"}, CFG)
    assert total == 20
    assert [f["factor"] for f in factors] == ["severity"]
    assert "Medium" in factors[0]["reason"]


def test_highest_severity_wins() -> None:
    assert score(["Low", "Critical", "High"], set(), CFG)[0] == 50


def test_each_tactic_beyond_the_first_adds_points() -> None:
    total, factors = score(["Medium"], {"Execution", "Persistence", "Discovery"}, CFG)
    assert total == 20 + 16
    assert factors[1]["points"] == 16 and "3 distinct" in factors[1]["reason"]


def test_progress_tactic_adds_once() -> None:
    total, factors = score(["Medium"], {"Credential Access", "Lateral Movement"}, CFG)
    assert total == 20 + 8 + 10
    assert "Credential Access and Lateral Movement" in factors[-1]["reason"]


def test_unknown_severity_scores_nothing() -> None:
    assert score(["Weird"], set(), CFG) == (0, [])


def test_cap_keeps_factors_summing_to_the_score() -> None:
    tactics = {f"T{i}" for i in range(10)} | {"Credential Access"}
    total, factors = score(["Critical"], tactics, CFG)
    assert total == 100
    assert sum(f["points"] for f in factors) == 100
    assert factors[-1]["factor"] == "cap"


@pytest.mark.parametrize(
    ("value", "want"),
    [(0, "Low"), (24, "Low"), (25, "Medium"), (49, "Medium"), (50, "High"), (74, "High"),
     (75, "Critical"), (100, "Critical")],
)  # fmt: skip
def test_label_boundaries(value: int, want: str) -> None:
    assert label(value, CFG) == want


def test_label_without_floors_is_low() -> None:
    cfg = RiskConfig({}, 0, frozenset(), 0, {}, 0, frozenset(), 0, {})
    assert label(99, cfg) == "Low"


def test_asset_privileged_and_public_ip_factors() -> None:
    total, factors = score(
        ["Medium"], set(), CFG, criticality=3, privileged=["b", "a"], public_ips=["8.8.8.8"]
    )
    assert total == 20 + 15 + 10 + 5
    assert [f["factor"] for f in factors] == ["severity", "asset", "privileged", "public_ip"]
    assert "a, b" in factors[2]["reason"] and "8.8.8.8" in factors[3]["reason"]


def test_criticality_one_and_unknown_score_nothing() -> None:
    assert score([], set(), CFG, criticality=1)[1] == []
    assert score([], set(), CFG, criticality=9)[1] == []
