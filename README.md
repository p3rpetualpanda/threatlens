# ThreatLens

![CI](https://github.com/p3rpetualpanda/threatlens/actions/workflows/ci.yml/badge.svg)

> v2 in progress; the v1 MVP is frozen at tag `v0.1.0`.

ThreatLens is the "handles it" half of the beacon / ThreatLens split: it turns
beacon's findings into prioritised, explained alerts with an analyst incident
workflow. It does no detection of its own.

## Current state (v2, M0)

- FastAPI app exposing `/health`.
- SQLite (WAL) with a numbered migrations runner: `app/migrations/NNN_name.sql`,
  versioned by `PRAGMA user_version`.
- First data model in place (see `app/migrations/001_initial.sql`);
  `assets` and `identities` are minimal until M4.
- Tooling: uv, ruff, mypy (strict), bandit, pip-audit, pytest. `make check` is the gate.

## Run locally

```powershell
uv sync
make demo
```

Open `http://127.0.0.1:8000/docs` for the API documentation.

To use a different database path:

```powershell
$env:THREATLENS_DB_PATH = "data\local-threatlens.db"
```

Run the checks:

```powershell
make check
```

## Responsible use

ThreatLens is for education and defensive analysis. It stores findings and analyst
notes from telemetry you own or are authorised to test. Do not connect it to systems
or telemetry that you do not own or have explicit permission to test.
