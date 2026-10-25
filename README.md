# ThreatLens

![CI](https://github.com/p3rpetualpanda/threatlens/actions/workflows/ci.yml/badge.svg)

> v2 in progress; the v1 MVP is frozen at tag `v0.1.0`.

ThreatLens is the "handles it" half of the beacon / ThreatLens split: it turns
beacon's findings into prioritised, explained alerts with an analyst incident
workflow. It does no detection of its own.

## Current state (v2, M2)

- FastAPI app: `/health`, ingest, and JSON login (`POST /api/v1/login`, `/logout`, `GET /me`).
- SQLite (WAL) with a numbered migrations runner: `app/migrations/NNN_name.sql`,
  versioned by `PRAGMA user_version`.
- Ingest: `POST /api/v1/findings` (bearer API key, 10 MB / 5,000-finding limits,
  all-or-nothing, idempotent by finding uid) and `threatlens import FILE`. Findings are
  validated against the vendored beacon contract v1 (`contracts/`). Incident correlation
  does not exist yet (M3).
- API keys: `threatlens create-api-key NAME` prints a token once; only its hash is stored.
- Accounts: argon2id passwords, roles viewer < analyst < lead < admin, server-side sessions
  (8 h idle expiry), CSRF header on state-changing requests, login lock after 5 failures per
  15 min, security headers. `threatlens create-admin EMAIL` makes the first admin (no default
  password). A test checks every route against every kind of caller.
- Audit log: append-only and hash-chained; `threatlens audit verify` exits 1 if a row was
  changed or removed. See [docs/threat-model.md](docs/threat-model.md).
- First data model in place (see `app/migrations/001_initial.sql`);
  `assets` and `identities` are minimal until M4.
- Tooling: uv, ruff, mypy (strict), bandit, pip-audit, pytest. `make check` is the gate.

## Run locally

```powershell
uv sync
make demo
```

Open `http://127.0.0.1:8000/docs` for the API documentation.

Import beacon findings (set `THREATLENS_DB_PATH` first, or pass `--db`):

```powershell
uv run threatlens import tests/fixtures/findings.jsonl
uv run threatlens create-api-key lab_a
uv run threatlens create-admin you@example.test
uv run threatlens audit verify
```

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
