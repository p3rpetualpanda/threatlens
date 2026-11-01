-- /metrics looks up the first take/assign per incident; without this it scans the whole log.
CREATE INDEX idx_audit_target_action ON audit_log (target, action);
