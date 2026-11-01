# What ThreatLens does

The full feature list, moved out of the README.

- FastAPI app: `/health`, ingest, and JSON login (`POST /api/v1/login`, `/logout`, `GET /me`).
- SQLite (WAL) with a numbered migrations runner: `app/migrations/NNN_name.sql`,
  versioned by `PRAGMA user_version`.
- Ingest: `POST /api/v1/findings` (bearer API key, 10 MB / 5,000-finding limits,
  all-or-nothing, idempotent by finding uid) and `threatlens import FILE`. Findings are
  validated against the vendored beacon contract v1 (`contracts/`).
- Correlation: after each ingest, alerts of an environment are grouped into incidents. Two
  alerts link when they share a host, user or source IP (not a stoplisted one) and their time
  ranges are within 2 h; incidents are the connected groups, with a plain-English reason per
  alert. Settings: `config/correlation.yml`. Analyst-touched incidents never split, resolved ones
  are frozen, ids are stable. Read-only `GET /api/v1/incidents` and `/{id}` for any logged-in
  role. Measured on beacon's 544-finding export: see [docs/correlation.md](correlation.md).
- Risk score (M4): every incident gets a 0-100 score from its highest alert severity, its
  distinct ATT&CK tactics, Credential Access / Lateral Movement, the most critical asset, a
  privileged identity and a public source IP in an authentication alert. The detail endpoint
  returns `risk_factors` (each with points and a reason, summing to the score) and `risk_label`.
  Weights: `config/risk.yml`. Assets and identities come from CSV files
  (`threatlens load-assets config/assets.csv`, `load-identities`), which replace the table and
  re-score every incident; the demo files are illustrative. IP class uses the standard library
  only, no lookups. ATT&CK 20.0 technique names, tactics and links come from the committed
  `app/data/attack_subset.json` (706 techniques), built by `scripts/build_attack_subset.py` from
  MITRE's bundle after a sha256 check; the incident detail lists them under `techniques`.
- Analyst actions (M5a, JSON only): `POST /api/v1/incidents/{id}/` `take`, `status`, `disposition`,
  `comments` (analyst+; an analyst works only incidents they own) and `assign`, `merge`, `split`
  (lead+). Resolving needs a disposition and copies it to alerts without one; reopening is for
  leads. Each action marks the incident touched and writes an audit row.
- Analyst pages (M5b, M5c): `/login`, `/` (queue by risk; filters status, environment, owner),
  `/incidents/{id}` (risk factors, ATT&CK links, entities with asset, identity and IP context,
  grouping reasons, timeline, comments) and `/alerts/{uid}` (the finding as received). Plain HTML
  forms run the same actions as the JSON API (take, status, disposition, comment; assign, merge,
  split for leads) and sign out. Buttons show only what the role and incident state allow; the
  service still enforces. Forms carry a hidden CSRF field and an Origin check. Jinja2 autoescape,
  no inline script or style, no JavaScript.
- Account: `/account` (your email in the header) lets any signed-in user change their own
  password. It needs the current one (wrong guesses share the 15-minute lock-out), ends their
  other sessions, and is audited without the password.
- Playbooks: each incident page shows a response checklist (containment, eradication, recovery,
  lessons learned) picked from the incident's ATT&CK techniques by the YAML files in
  `config/playbooks/` (exact technique, parent, tactic, then a default). Ticking a step is audited.
  D3FEND ids come from a pinned list in `config/playbooks/d3fend.txt`.
- Reports: `/incidents/{id}/report` is a printable page and `/incidents/{id}/report.md` a Markdown
  download (any signed-in role). Summary, scope, timeline, techniques, risk factors, checklist,
  audited actions and disposition; every stored value is escaped. Merged incidents are 404.
- Metrics: `/metrics` (any signed-in role) shows alerts per incident, MTTA (creation to first
  owner, from the audit log), MTTR (resolved incidents) and dispositions with a false-positive
  rate per rule. Merged-away incidents are left out; no data shows "n/a".
- Verdicts back to beacon: `threatlens export-verdicts --out FILE` writes `alert_id,status,reason`
  for every alert with a disposition (`benign_true_positive` becomes `closed`). It refuses an
  existing file, so beacon's `detections/verdicts.csv` is never overwritten. Apply with
  `beacon detect --verdicts FILE`. Beacon only changes alerts still `new`; the rest are reported
  as conflicts. `scripts/roundtrip_beacon.py ../beacon` shows it: on the fixture, a false-positive
  verdict took R01's precision from 1.0 to 0.0, a true positive left R05 at 1.0 with one verdict,
  and the benign one did not move R20.
- API keys: `threatlens create-api-key NAME` prints a token once; only its hash is stored.
- Admin pages (M5d): a fixed one-shot message after each good action. `/audit` (lead and admin)
  lists the newest 50 audit rows (leads do not see login rows; admins do) and the hash-chain result (new rows checked on every view; the whole chain every 10 minutes, or every view if the append-only triggers are gone).
  `/admin/keys` (admin only) lists, creates and revokes ingest keys; a new token is shown once,
  on the page after the create redirect, and never logged (a 60 s HttpOnly cookie carries it across the redirect; the database never holds it; the cookie is `Secure` off localhost).
  `/admin/users` (admin only) creates users (admin types the first password), changes roles and
  disables or re-enables accounts. You cannot change your own account, and the last active admin
  stays. Disabling ends that user's sessions and blocks login. Every change is audited. A
  forgotten password is reset by an operator with `threatlens user set-password EMAIL`; everyone
  can change their own on `/account`.
- Accounts: argon2id passwords, roles viewer < analyst < lead < admin, server-side sessions
  (8 h idle expiry, 24 h hard limit), CSRF header on state-changing requests, login lock after 5 failures per
  15 min, security headers. `threatlens create-admin EMAIL` makes the first admin (no default
  password). A test checks every route against every kind of caller.
- Audit log: hash-chained and append-only through SQL; `threatlens audit verify` exits 1 if a row was changed or removed. Optional keyed anchors (see the README) catch a full rewrite.
  It catches accidental and naive edits, not someone who can rewrite the file. See [docs/threat-model.md](threat-model.md).
- First data model in place (see `app/migrations/001_initial.sql`);
  `assets` and `identities` gained their columns in migration 006.
- Tooling: uv, ruff, mypy (strict), bandit, pip-audit, pytest. `make check` is the gate.
- Known limit: no host-to-network correlation on the demo data. Beacon's Zeek logs and host logs are 2 d 2 h (day 1) and 1 d 1 h (day 2) apart, and OTRF's docs do not say whether they are the same run, so findings from the two are never linked.

