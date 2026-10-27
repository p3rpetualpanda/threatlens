from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.correlate import Alert, partition
from app.correlation_config import load_config


def test_load_config_defaults() -> None:
    cfg = load_config()
    assert cfg.link_window == timedelta(hours=2)
    assert "system" in cfg.ignored_users
    assert cfg.auto_share == 0.2
    assert cfg.auto_min_alerts == 50


def test_load_config_rejects_unknown_key(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(
        "link_window_minutes: 1\nignored_users: []\nignore_machine_accounts: true\n"
        "auto_share: 0.2\nauto_min_alerts: 50\nbogus: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="bogus"):
        load_config(p)


T0 = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
CFG = load_config()


def mk(uid: str, minutes: int, *ents: tuple[str, str], rule: str = "R", dur: int = 0) -> Alert:
    start = T0 + timedelta(minutes=minutes)
    return Alert(uid, rule, start, start + timedelta(minutes=dur), frozenset(ents))


def groups(alerts: list[Alert]) -> set[frozenset[str]]:
    return {c.uids for c in partition(alerts, CFG)}


def test_shared_host_within_window_links() -> None:
    assert groups([mk("a", 0, ("host", "h")), mk("b", 30, ("host", "h"))]) == {
        frozenset({"a", "b"})
    }


def test_gap_over_window_does_not_link() -> None:
    a, b = mk("a", 0, ("host", "h")), mk("b", 121, ("host", "h"))
    assert groups([a, b]) == {frozenset({"a"}), frozenset({"b"})}


def test_gap_exactly_window_links() -> None:
    assert len(groups([mk("a", 0, ("host", "h")), mk("b", 120, ("host", "h"))])) == 1


def test_gap_counts_from_end_of_earlier_range() -> None:
    a, b = mk("a", 0, ("host", "h"), dur=100), mk("b", 200, ("host", "h"))
    assert len(groups([a, b])) == 1


def test_dst_ip_and_process_never_link() -> None:
    a = mk("a", 0, ("dst_ip", "203.0.113.5"), ("process", "x.exe"))
    b = mk("b", 1, ("dst_ip", "203.0.113.5"), ("process", "x.exe"))
    assert len(groups([a, b])) == 2


@pytest.mark.parametrize("user", ["system", "WS01$", "-", "SYSTEM"])
def test_stoplisted_user_does_not_link(user: str) -> None:
    assert len(groups([mk("a", 0, ("user", user)), mk("b", 1, ("user", user))])) == 2


def test_entity_case_insensitive() -> None:
    assert len(groups([mk("a", 0, ("host", "Scranton")), mk("b", 1, ("host", "scranton"))])) == 1


def test_chain_links_transitively() -> None:
    a = mk("a", 0, ("host", "h"))
    b = mk("b", 100, ("host", "h"), ("user", "u"))
    c = mk("c", 200, ("user", "u"))
    assert groups([a, b, c]) == {frozenset("abc")}


def test_alert_with_no_linking_entities_is_alone() -> None:
    comps = partition([mk("a", 0, ("user", "system"))], CFG)
    assert [c.uids for c in comps] == [frozenset({"a"})]
    assert comps[0].why == {"a": "first alert in incident"}


def test_auto_stoplist_needs_50_alerts() -> None:
    same = [mk(f"u{i:02}", 0, ("host", "h")) for i in range(49)]
    assert len(groups(same)) == 1
    same.append(mk("u49", 0, ("host", "h")))
    comps = partition(same, CFG)
    assert len(comps) == 50
    assert all(c.too_common == {"host:h"} for c in comps)


def _share(n_shared: int, total: int) -> int:
    alerts = [mk(f"s{i:03}", 0, ("host", "h")) for i in range(n_shared)]
    alerts += [mk(f"o{i:03}", 0, ("host", f"x{i}")) for i in range(total - n_shared)]
    return len(partition(alerts, CFG)) - (total - n_shared)  # components made by shared group


def test_auto_stoplist_boundary_20_percent() -> None:
    assert _share(20, 100) == 1  # exactly 20% still links
    assert _share(21, 100) == 21  # 21% stops linking


def test_why_names_entity_and_gap() -> None:
    a = mk("a", 0, ("host", "scranton"), rule="R05")
    b = mk("b", 12, ("host", "scranton"), rule="R07")
    why = next(iter(partition([b, a], CFG))).why
    assert why["a"] == "first alert in incident"
    assert why["b"] == "shares host `scranton` with alert R05 (12 min apart)"


def test_alert_linked_only_to_later_alert_still_explained() -> None:
    a = mk("a", 0, ("host", "h1"))
    x = mk("x", 60, ("host", "h2"), ("user", "u"))
    b = mk("b", 90, ("user", "u"), ("host", "h1"))
    why = next(iter(partition([a, x, b], CFG))).why
    assert "later alert" in why["x"] or "shares" in why["x"]


def test_inverted_range_does_not_crash() -> None:
    a = Alert("a", "R", T0 + timedelta(minutes=10), T0, frozenset({("host", "h")}))
    assert len(groups([a, mk("b", 20, ("host", "h"))])) == 1
