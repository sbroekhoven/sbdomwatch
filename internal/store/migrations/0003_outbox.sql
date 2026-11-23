-- Outbox retry schedule: when the next delivery attempt is due.
ALTER TABLE event_deliveries ADD COLUMN next_attempt_at TEXT;
CREATE INDEX event_deliveries_due ON event_deliveries (delivered_at, next_attempt_at);
