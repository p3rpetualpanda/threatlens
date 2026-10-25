"""Settings read once at import. Tests monkeypatch `DB_PATH`; callers read it at call time."""

from __future__ import annotations

import os
from pathlib import Path

# Absolute, so the CLI and the server agree whatever folder they are started from.
DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "threatlens.db"
DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", DEFAULT_DB))
