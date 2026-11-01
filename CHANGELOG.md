# Changelog

## 1.0.1 - 2026-11-01

- Accessibility: checkboxes and links are at least 24 px (WCAG 2.5.8), with a test; CSS lint fixes.

## 1.0.0 - 2026-11-01

- M0 foundation: FastAPI app, `/health`, numbered SQLite migrations, 13-table data model.
- M1 ingest: `POST /api/v1/findings`, `threatlens import`, API keys, beacon contract v1.
- M2 accounts: argon2id passwords, four roles, sessions, CSRF, login lock, hash-chained audit log.
- M3 correlation: alerts grouped into incidents with a reason per alert.
- M4 risk score: 0-100 with every factor explained; assets and identities from CSV.
- M5 analyst workflow: JSON API and HTML pages, admin pages, audit anchors, ingest throttle.
- M6 playbooks, incident reports and the `/metrics` page.
- M7 `threatlens export-verdicts`: dispositions back to beacon, with a round-trip check.
- M8 `docker compose up` demo on beacon's 544 findings, `scripts/readme_numbers.py`,
  `decisions.md`.

The v1 MVP (detection rules, dashboard) is frozen at tag `v0.1.0`.
