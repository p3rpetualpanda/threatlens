"""One-shot messages handed from a POST to the page it redirects to, keyed by session.

The redirect target stays a plain URL, so a refresh or a typed `?done=` cannot replay or fake
a message, and a one-time API token never rides in a URL.
shortcut: in-process memory, so it needs one worker (the demo setup) and a restart drops a
pending message; move it to the database before running several workers.
"""

from __future__ import annotations

import time
from typing import Any

_TTL = 60.0
_slots: dict[tuple[str, str], tuple[float, Any]] = {}


def put(session_key: str, kind: str, value: Any) -> None:
    now = time.monotonic()
    for k in [k for k, (at, _) in _slots.items() if now - at > _TTL]:
        del _slots[k]
    _slots[(session_key, kind)] = (now, value)


def pop(session_key: str, kind: str) -> Any | None:
    entry = _slots.pop((session_key, kind), None)
    if entry is None or time.monotonic() - entry[0] > _TTL:
        return None
    return entry[1]
