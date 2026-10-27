"""Settings read once at import. Tests monkeypatch `DB_PATH`; callers read it at call time."""

from __future__ import annotations

import os
from pathlib import Path

# Absolute, so the CLI and the server agree whatever folder they are started from.
DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "threatlens.db"
DB_PATH = Path(os.environ.get("THREATLENS_DB_PATH", DEFAULT_DB))
# API docs (Swagger UI, ReDoc, openapi.json) are off unless THREATLENS_DOCS=1: Swagger loads
# scripts from a CDN, so its pages carry no CSP. `make demo` turns them on.
DOCS_ENABLED = os.environ.get("THREATLENS_DOCS") == "1"
# Audit anchoring (app/anchor.py): a key file and an append-only anchor file; both optional.
AUDIT_KEY_FILE = os.environ.get("THREATLENS_AUDIT_KEY_FILE")
AUDIT_ANCHOR = os.environ.get("THREATLENS_AUDIT_ANCHOR")
