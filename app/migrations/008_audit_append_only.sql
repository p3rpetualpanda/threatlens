-- 008_audit_append_only.sql — the audit log can be added to but not edited or deleted through SQL.
-- Whoever can write the database file can still drop these triggers; app/audit.py `append_only`
-- notices that, and the audit page then re-checks the whole chain on every view.
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
