CREATE INDEX idx_alert_entities_alert ON alert_entities (alert_id);
CREATE INDEX idx_alert_entities_kind_value ON alert_entities (kind, value);
