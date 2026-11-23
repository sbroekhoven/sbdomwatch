-- Diff engine state per watch: accepted baseline, pending changes and
-- baseline samples (JSON, see internal/diff.State).
ALTER TABLE watches ADD COLUMN diff_state TEXT NOT NULL DEFAULT '{}';
