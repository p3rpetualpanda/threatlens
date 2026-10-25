-- 004_login_attempts.sql — failed logins, counted per username and per IP (spec §6.4).
CREATE TABLE login_attempts (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,   -- 'user:<lower-cased email>' or 'ip:<address>'
    at  TEXT NOT NULL
);
CREATE INDEX idx_login_attempts_key_at ON login_attempts (key, at);
