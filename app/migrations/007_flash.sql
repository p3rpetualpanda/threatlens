-- 007_flash.sql — one-shot messages from a POST to the page it redirects to (app/flash.py).
-- Rows live for 60 s at most and are deleted when read. `value` can hold a new API token.
CREATE TABLE flash (
    session_key TEXT NOT NULL,   -- sha256 of the session's CSRF token
    kind        TEXT NOT NULL,   -- 'done' or 'key'
    value       TEXT NOT NULL,   -- JSON
    at          TEXT NOT NULL,
    PRIMARY KEY (session_key, kind)
);
