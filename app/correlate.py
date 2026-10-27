"""Pure correlation: group alerts into components (spec 6.4). No database, no clock.

Two alerts link when they share a host, user or src_ip that is not stoplisted and their time
ranges are within ``link_window``. Components are the connected groups. The result depends only
on the set of alerts, never on the order they are passed in.

shortcut: every alert of an environment is re-partitioned on each ingest; fine to a few thousand
alerts, needs an incremental version beyond ~50k.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from app.correlation_config import CorrelationConfig

LINK_KINDS = ("host", "user", "src_ip")  # dst_ip and process never link
_FIRST = "first alert in incident"


@dataclass(frozen=True)
class Alert:
    uid: str
    rule: str
    first_seen: datetime
    last_seen: datetime
    entities: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class Component:
    uids: frozenset[str]
    why: dict[str, str]
    too_common: frozenset[str]


def _pivots(alert: Alert, cfg: CorrelationConfig) -> frozenset[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for kind, value in alert.entities:
        v = value.strip().lower()
        if kind not in LINK_KINDS or not v:
            continue
        if kind == "user" and (
            v in cfg.ignored_users or (cfg.ignore_machine_accounts and v.endswith("$"))
        ):
            continue
        out.add((kind, v))
    return frozenset(out)


def partition(alerts: list[Alert], cfg: CorrelationConfig) -> list[Component]:
    order = sorted(alerts, key=lambda a: (a.first_seen, a.uid))
    pivots = {a.uid: _pivots(a, cfg) for a in order}

    counts: dict[tuple[str, str], int] = defaultdict(int)
    for p in pivots.values():
        for e in p:
            counts[e] += 1
    common: frozenset[tuple[str, str]] = frozenset()
    if len(order) >= cfg.auto_min_alerts:
        common = frozenset(e for e, n in counts.items() if n / len(order) > cfg.auto_share)

    buckets: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for a in order:
        for e in pivots[a.uid] - common:
            buckets[e].append(a)

    parent = {a.uid: a.uid for a in order}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    # edges[uid] -> candidate (rank, text) pairs, rank makes the choice order-independent
    earlier: dict[str, list[tuple[tuple[object, ...], str]]] = defaultdict(list)
    later: dict[str, list[tuple[tuple[object, ...], str]]] = defaultdict(list)
    window = cfg.link_window
    for (kind, value), members in buckets.items():
        ends = [max(m.first_seen, m.last_seen) for m in members]
        prefix_max: list[datetime] = []
        for end in ends:
            prefix_max.append(end if not prefix_max else max(prefix_max[-1], end))
        for i, b in enumerate(members):
            threshold = b.first_seen - window
            j = i - 1
            while j >= 0 and prefix_max[j] >= threshold:
                a = members[j]
                if ends[j] >= threshold:
                    gap = max(0, int((b.first_seen - ends[j]).total_seconds()))
                    mins = gap // 60
                    rank = (gap, a.first_seen, a.uid, kind, value)
                    earlier[b.uid].append(
                        (rank, f"shares {kind} `{value}` with alert {a.rule} ({mins} min apart)")
                    )
                    rank = (gap, b.first_seen, b.uid, kind, value)
                    later[a.uid].append(
                        (
                            rank,
                            f"shares {kind} `{value}` with later alert {b.rule} ({mins} min apart)",
                        )
                    )
                    parent[find(a.uid)] = find(b.uid)
                j -= 1

    groups: dict[str, list[Alert]] = defaultdict(list)
    for a in order:
        groups[find(a.uid)].append(a)

    components = []
    for members in groups.values():  # members are already in (first_seen, uid) order
        why = {}
        for k, a in enumerate(members):
            if k == 0:
                why[a.uid] = _FIRST
            elif earlier[a.uid]:
                why[a.uid] = min(earlier[a.uid], key=lambda c: c[0])[1]
            else:
                why[a.uid] = min(later[a.uid], key=lambda c: c[0])[1]
        too_common = frozenset(f"{k}:{v}" for m in members for k, v in pivots[m.uid] & common)
        components.append(Component(frozenset(a.uid for a in members), why, too_common))
    components.sort(key=lambda c: min(c.uids))
    return components
