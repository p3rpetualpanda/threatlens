# ThreatLens

ThreatLens is an explainable blue-team threat detection and incident-response MVP. It turns safe, deterministic synthetic security events into prioritized alerts with evidence, MITRE ATT&CK technique references, and analyst workflow fields.



## Current MVP

- FastAPI service with `/health`, `/api/alerts`, and alert status updates.
- SQLite persistence stores events, derived alerts, and analyst status updates across restarts.
- The database path is configurable with `THREATLENS_DB_PATH` and defaults to `data/threatlens.db`; an empty database is seeded once with the deterministic demo events.
- `POST /api/events` accepts a validated security event, persists it, and recomputes the alert list.
- Deterministic seed data covering brute force, valid-account anomalies, encoded PowerShell, and large outbound transfers.
- Evidence and recommendations attached to each alert.
- Minimal dashboard at `/`.
- Unit and API tests.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --reload-dir app
```

Open `http://127.0.0.1:8000/` for the dashboard or `http://127.0.0.1:8000/docs` for the API documentation.

To use a different database path in PowerShell:

```powershell
$env:THREATLENS_DB_PATH = "data\local-threatlens.db"
```

Run tests:

```powershell
python -m pytest
```



## Responsible use

ThreatLens is for education and defensive analysis. It uses documentation-safe IP ranges and synthetic events. Do not connect it to systems or telemetry that you do not own or have explicit permission to test.
