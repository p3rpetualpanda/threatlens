-- 005_correlation.sql — correlation into incidents (M3). Additive only.
ALTER TABLE incident_alerts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incident_alerts ADD COLUMN why TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN related_incident TEXT REFERENCES incidents(id);
ALTER TABLE incidents ADD COLUMN touched INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_incident_alerts_alert ON incident_alerts (alert_id);
