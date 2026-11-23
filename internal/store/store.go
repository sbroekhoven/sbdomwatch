// Package store keeps watches, observations, events and the audit log in
// SQLite. All writes go through one connection; reads use a small pool.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// ErrNotFound is returned when a watch does not exist.
var ErrNotFound = errors.New("not found")

const (
	busyTimeout = 5 * time.Second
	readConns   = 4
	timeFormat  = time.RFC3339
)

// Store is the SQLite store.
type Store struct {
	w   *sql.DB // single writer connection
	r   *sql.DB // read-only pool
	now func() time.Time
}

// Options configure Open.
type Options struct {
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// Open opens or creates the database at path and applies migrations.
func Open(ctx context.Context, path string, opts Options) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	pragmas := url.Values{}
	pragmas.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
	pragmas.Add("_pragma", "foreign_keys(1)")
	pragmas.Add("_pragma", "temp_store(MEMORY)")

	wq := url.Values{"_txlock": {"immediate"}}
	for _, p := range pragmas["_pragma"] {
		wq.Add("_pragma", p)
	}
	wq.Add("_pragma", "journal_mode(WAL)")
	wq.Add("_pragma", "synchronous(NORMAL)")
	w, err := sql.Open("sqlite", "file:"+path+"?"+wq.Encode())
	if err != nil {
		return nil, fmt.Errorf("store: open writer: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)

	s := &Store{w: w, now: now}
	if err := w.PingContext(ctx); err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := s.migrate(ctx); err != nil {
		w.Close()
		return nil, err
	}

	rq := pragmas
	rq.Add("_pragma", "query_only(1)")
	r, err := sql.Open("sqlite", "file:"+path+"?"+rq.Encode())
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open reader: %w", err)
	}
	r.SetMaxOpenConns(readConns)
	if err := r.PingContext(ctx); err != nil {
		w.Close()
		r.Close()
		return nil, fmt.Errorf("store: open reader: %w", err)
	}
	s.r = r
	return s, nil
}

// Close closes both connection pools.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error {
	return s.r.PingContext(ctx)
}

// writeTx runs fn in an immediate transaction on the writer connection.
func (s *Store) writeTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: bad time %q: %w", s, err)
	}
	return t.UTC(), nil
}

func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
