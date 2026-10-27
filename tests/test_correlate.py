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


def test_dense_bucket_stays_small() -> None:
    import tracemalloc

    alerts = [Alert(f"a{i:04}", "R", T0, T0, frozenset({("host", "h")})) for i in range(800)]
    alerts += [mk(f"b{i:04}", 5000 + i, ("host", f"x{i}")) for i in range(3200)]
    tracemalloc.start()
    try:
        comps = partition(alerts, CFG)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(comps) == 3201
    assert peak < 40_000_000  # the pair lists this replaced took ~150 MB here


def test_src_ip_links_and_values_are_trimmed_and_lowered() -> None:
    assert groups(
        [mk("a", 0, ("src_ip", "203.0.113.5")), mk("b", 5, ("src_ip", "203.0.113.5"))]
    ) == {frozenset({"a", "b"})}
    assert groups([mk("a", 0, ("host", " H1 ")), mk("b", 5, ("host", "h1"))]) == {
        frozenset({"a", "b"})
    }


def test_blank_values_never_link() -> None:
    assert len(groups([mk("a", 0, ("host", "  ")), mk("b", 5, ("host", "  "))])) == 2


def test_overlapping_ranges_are_zero_minutes_apart() -> None:
    (c,) = partition([mk("a", 0, ("host", "h"), dur=60), mk("b", 10, ("host", "h"))], CFG)
    assert "0 min apart" in c.why["b"]


def test_why_names_the_nearest_earlier_alert() -> None:
    alerts = [
        mk("a", 0, ("host", "h"), rule="FAR"),
        mk("b", 50, ("host", "h"), rule="NEAR"),
        mk("c", 60, ("host", "h")),
    ]
    (c,) = partition(alerts, CFG)
    assert "NEAR" in c.why["c"] and "FAR" not in c.why["c"]


def test_alert_with_no_earlier_link_names_its_nearest_later_partner() -> None:
    # x joins the component only through later alerts (z, y), which share its host
    alerts = [
        mk("a", 0, ("user", "u")),
        mk("x", 100, ("host", "h2")),
        mk("z", 105, ("host", "h2"), rule="NEARER"),
        mk("y", 110, ("host", "h2"), ("user", "u"), rule="FARTHER"),
    ]
    (c,) = partition(alerts, CFG)
    assert "later alert NEARER" in c.why["x"]


def test_inverted_range_still_links_by_its_start() -> None:
    inverted = Alert("a", "R", T0 + timedelta(minutes=30), T0, frozenset({("host", "h")}))
    assert groups([inverted, mk("b", 60, ("host", "h"))]) == {frozenset({"a", "b"})}


def test_components_come_back_in_uid_order() -> None:
    alerts = [mk("c", 0, ("host", "x")), mk("a", 500, ("host", "y")), mk("b", 1000, ("host", "z"))]
    assert [min(c.uids) for c in partition(alerts, CFG)] == ["a", "b", "c"]


def test_order_independent_with_auto_stoplist_active() -> None:
    import random

    alerts = [mk(f"h{i:02}", i, ("host", "hot"), ("user", f"u{i % 7}")) for i in range(60)]
    alerts += [mk(f"q{i:02}", i * 3, ("host", f"c{i % 5}")) for i in range(20)]
    want = sorted((sorted(c.uids), sorted(c.too_common)) for c in partition(alerts, CFG))
    assert any(c.too_common for c in partition(alerts, CFG))
    for seed in range(5):
        shuffled = alerts[:]
        random.Random(seed).shuffle(shuffled)  # noqa: S311 (test shuffle)
        got = sorted((sorted(c.uids), sorted(c.too_common)) for c in partition(shuffled, CFG))
        assert got == want
