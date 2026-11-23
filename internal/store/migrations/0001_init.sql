-- Initial schema. Times are UTC RFC3339 text; domains are normalized.

CREATE TABLE watches (
  id                    INTEGER PRIMARY KEY,
  domain                TEXT NOT NULL UNIQUE,
  template              TEXT NOT NULL,   -- owned | candidate | third-party
  state                 TEXT NOT NULL,   -- new | baselining | active | paused | archived
  interval_sec          INTEGER NOT NULL,
  next_check_at         TEXT NOT NULL,
  baseline_started_at   TEXT,
  baseline_completed_at TEXT,
  volatile_fields       TEXT NOT NULL DEFAULT '[]',  -- JSON list of field paths to ignore
  tags                  TEXT NOT NULL DEFAULT '{}',  -- JSON map
  expires_at            TEXT,            -- candidates only
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

CREATE INDEX watches_due ON watches (state, next_check_at);

CREATE TABLE watch_origins (
  watch_id  INTEGER NOT NULL REFERENCES watches(id),
  origin    TEXT NOT NULL,               -- manual | typosquat | incident | intel
  reason    TEXT NOT NULL CHECK (length(reason) > 0),
  reference TEXT,
  added_by  TEXT NOT NULL,
  added_at  TEXT NOT NULL,
  PRIMARY KEY (watch_id, origin, reason)
);

CREATE TABLE observations (
  id          INTEGER PRIMARY KEY,
  watch_id    INTEGER NOT NULL REFERENCES watches(id),
  check_name  TEXT NOT NULL,             -- dns | rdap
  observed_at TEXT NOT NULL,
  is_baseline INTEGER NOT NULL DEFAULT 0,
  data        TEXT NOT NULL,             -- canonical JSON
  hash        TEXT NOT NULL
);

CREATE INDEX observations_watch ON observations (watch_id, check_name, observed_at);

CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  watch_id    INTEGER NOT NULL REFERENCES watches(id),
  type        TEXT NOT NULL,
  severity    TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload     TEXT NOT NULL              -- JSON: origins, reason, diff
);

CREATE INDEX events_watch ON events (watch_id, occurred_at);
CREATE INDEX events_time ON events (occurred_at);

CREATE TABLE event_deliveries (          -- the outbox, one row per event and sink
  event_id     INTEGER NOT NULL REFERENCES events(id),
  sink         TEXT NOT NULL,
  delivered_at TEXT,
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_error   TEXT,
  PRIMARY KEY (event_id, sink)
);

CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY,
  at       TEXT NOT NULL,
  actor    TEXT NOT NULL,
  action   TEXT NOT NULL,
  watch_id INTEGER,
  detail   TEXT
);

CREATE INDEX audit_log_watch ON audit_log (watch_id, at);
