"""Settings read once at import. Tests monkeypatch `DB_PATH`; callers read it at call time."""

from __future__ import annotations

import os
from pathlib import Path

DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", "data/threatlens.db"))
