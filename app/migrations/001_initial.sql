-- 001_initial.sql — ThreatLens v2 first data model (spec §6.2).
-- assets and identities are intentionally minimal now; their columns are finalized in M4.

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('viewer', 'analyst', 'lead', 'admin')),
    created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE api_keys (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE environments (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    last_import_at TEXT
);

CREATE TABLE alerts (
    id               TEXT PRIMARY KEY,
    finding_info_uid TEXT NOT NULL UNIQUE,
    raw_json         TEXT NOT NULL,
    time             TEXT,
    severity         TEXT NOT NULL,
    rule             TEXT NOT NULL,
    technique        TEXT,
    tactic           TEXT,
    environment      TEXT NOT NULL,
    disposition      TEXT
                     CHECK (disposition IN ('true_positive', 'benign_true_positive', 'false_positive')),
    beacon_status    TEXT,
    last_ingested_at TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE alert_entities (
    id       TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    kind     TEXT NOT NULL
             CHECK (kind IN ('host', 'user', 'src_ip', 'dst_ip', 'process')),
    value    TEXT NOT NULL
);

CREATE TABLE incidents (
    id           TEXT PRIMARY KEY,
    environment  TEXT NOT NULL,
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'new'
                 CHECK (status IN ('new', 'in_progress', 'resolved')),
    disposition  TEXT
                 CHECK (disposition IN ('true_positive', 'benign_true_positive', 'false_positive')),
    owner        TEXT REFERENCES users(id),
    risk_score   INTEGER
                 CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)),
    risk_factors TEXT,
    first_seen   TEXT,
    last_seen    TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    resolved_at  TEXT,
    merged_into  TEXT REFERENCES incidents(id)
);

CREATE TABLE incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    alert_id    TEXT NOT NULL REFERENCES alerts(id),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE comments (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    author      TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE playbook_progress (
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    step        TEXT NOT NULL,
    done        INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (incident_id, step)
);

-- Tamper-evident chain: each row's hash covers the previous row's hash (spec §6.2).
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT,
    prev_hash TEXT,
    hash      TEXT
);

-- Minimal now; columns finalized in M4 (spec §6.2 / §6.5).
CREATE TABLE assets (
    id   TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE identities (
    id   TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
