-- Baseline confirmation for owned domains and the time of the last
-- observation (for ls --stale).
ALTER TABLE watches ADD COLUMN baseline_confirmed_at TEXT;
ALTER TABLE watches ADD COLUMN baseline_confirmed_by TEXT;
ALTER TABLE watches ADD COLUMN last_observed_at TEXT;
UPDATE watches SET last_observed_at = (SELECT MAX(observed_at) FROM observations o WHERE o.watch_id = watches.id);
