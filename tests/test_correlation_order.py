"""The partition must depend only on the set of alerts, not on arrival order or batch sizes."""

from __future__ import annotations

import random
import tempfile
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from incident_helpers import add

from app.correlate import Alert, partition
from app.correlation_config import load_config
from app.db import connect, migrate
from app.incidents import recorrelate

CFG = load_config()
T0 = datetime(2026, 1, 1, tzinfo=UTC)

# (minutes from T0, host, user); small pools force many collisions, "-" and "SYSTEM" are stoplisted
specs = st.lists(
    st.tuples(
        st.integers(0, 24 * 60),
        st.sampled_from(["h1", "H1", "h2", "h3", None]),
        st.sampled_from(["u1", "U1", "u2", "SYSTEM", "-", None]),
    ),
    min_size=1,
    max_size=14,  # stays under the auto-stoplist minimum, which is deliberately not monotone
)


def _alerts(items: list[tuple[int, str | None, str | None]], span: bool = True) -> list[Alert]:
    out = []
    for i, (m, host, user) in enumerate(items):
        ents = frozenset(
            (kind, value) for kind, value in (("host", host), ("user", user)) if value is not None
        )
        start = T0 + timedelta(minutes=m)
        out.append(
            Alert(
                f"a{i:02}",
                f"R{i % 3}",
                start,
                start + timedelta(minutes=i % 4 if span else 0),
                ents,
            )
        )
    return out


@given(specs, st.randoms(use_true_random=False))
def test_partition_ignores_input_order(
    items: list[tuple[int, str | None, str | None]], rnd: random.Random
) -> None:
    alerts = _alerts(items)
    shuffled = alerts[:]
    rnd.shuffle(shuffled)
    assert partition(alerts, CFG) == partition(shuffled, CFG)


@settings(max_examples=40, deadline=None)
@given(specs, st.randoms(use_true_random=False), st.integers(1, 4))
def test_partition_ignores_batch_split(
    items: list[tuple[int, str | None, str | None]], rnd: random.Random, batches: int
) -> None:
    expected = {c.uids for c in partition(_alerts(items, span=False), CFG)}
    order = list(range(len(items)))
    rnd.shuffle(order)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.db"
        migrate(path)
        with closing(connect(path)) as conn:
            for chunk in (order[k::batches] for k in range(batches)):
                for i in chunk:
                    m, host, user = items[i]
                    add(conn, f"a{i:02}", m, host=host, user=user, rule=f"R{i % 3}")
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                recorrelate(conn, "e", T0)
                conn.commit()
            groups: dict[str, set[str]] = {}
            for r in conn.execute(
                "SELECT ia.incident_id, ia.alert_id FROM incident_alerts ia "
                "JOIN incidents i ON i.id = ia.incident_id WHERE i.merged_into IS NULL"
            ):
                groups.setdefault(r["incident_id"], set()).add(r["alert_id"])
    assert {frozenset(g) for g in groups.values()} == expected
