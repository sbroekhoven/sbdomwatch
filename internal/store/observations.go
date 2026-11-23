package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// CheckableStates are the states the scheduler checks.
var CheckableStates = []watch.State{watch.StateNew, watch.StateBaselining, watch.StateActive}

// Due is a watch claimed for checking.
type Due struct {
	ID          int64
	Domain      string
	State       watch.State
	IntervalSec int
}

// ClaimDue returns up to limit checkable watches whose next_check_at is at
// or before now, oldest first, and moves their next_check_at to now+lease so
// no other claim picks them up while they are being checked.
func (s *Store) ClaimDue(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Due, error) {
	var due []Due
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(CheckableStates)), ",")
		args := make([]any, 0, len(CheckableStates)+2)
		for _, st := range CheckableStates {
			args = append(args, string(st))
		}
		args = append(args, formatTime(now), limit)
		rows, err := tx.QueryContext(ctx, `SELECT id, domain, state, interval_sec FROM watches
			WHERE state IN (`+placeholders+`) AND next_check_at <= ?
			ORDER BY next_check_at, id LIMIT ?`, args...)
		if err != nil {
			return fmt.Errorf("store: query due watches: %w", err)
		}
		for rows.Next() {
			var d Due
			if err := rows.Scan(&d.ID, &d.Domain, &d.State, &d.IntervalSec); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan due watch: %w", err)
			}
			due = append(due, d)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("store: query due watches: %w", err)
		}
		leased := formatTime(now.Add(lease))
		for _, d := range due {
			if _, err := tx.ExecContext(ctx, `UPDATE watches SET next_check_at = ? WHERE id = ?`, leased, d.ID); err != nil {
				return fmt.Errorf("store: lease watch %s: %w", d.Domain, err)
			}
		}
		return nil
	})
	return due, err
}

// CheckResult is what a ProcessFunc decides after one check round.
type CheckResult struct {
	Watch        watch.Watch // new state, baseline fields and volatile fields
	Diff         diff.State
	Observations []check.Observation
	Baseline     bool // observations belong to the baseline
	Events       []events.Event
	Routes       [][]string // per event (same index): the sinks to deliver it to
	Next         time.Time  // next check
}

// ProcessFunc turns the current watch and diff state into a CheckResult.
// It runs inside the write transaction and must not do I/O.
type ProcessFunc func(w watch.Watch, st diff.State) (CheckResult, error)

// ApplyCheck loads the watch and its diff state, lets process decide, and
// stores the observations, the new watch and diff state and the events in
// one transaction. It returns the stored events with their IDs, or
// ErrNotFound if the watch was deleted meanwhile.
func (s *Store) ApplyCheck(ctx context.Context, watchID int64, process ProcessFunc) ([]events.Event, error) {
	var stored []events.Event
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		ws, err := queryWatches(ctx, tx, selectWatch+" WHERE w.id = ?", watchID)
		if err != nil {
			return err
		}
		if len(ws) == 0 {
			return fmt.Errorf("watch %d: %w", watchID, ErrNotFound)
		}
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT diff_state FROM watches WHERE id = ?`, watchID).Scan(&raw); err != nil {
			return fmt.Errorf("store: read diff state: %w", err)
		}
		var st diff.State
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return fmt.Errorf("store: decode diff state of %s: %w", ws[0].Domain, err)
		}

		res, err := process(ws[0], st)
		if err != nil {
			return err
		}
		res.Watch.ID = watchID
		res.Watch.NextCheckAt = res.Next
		for _, o := range res.Observations {
			if t := o.ObservedAt.UTC().Truncate(time.Second); res.Watch.LastObservedAt == nil || t.After(*res.Watch.LastObservedAt) {
				res.Watch.LastObservedAt = &t
			}
		}
		if _, err := saveWatch(ctx, tx, res.Watch); err != nil {
			return err
		}
		stJSON, err := json.Marshal(res.Diff)
		if err != nil {
			return fmt.Errorf("store: encode diff state: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE watches SET diff_state = ? WHERE id = ?`, string(stJSON), watchID); err != nil {
			return fmt.Errorf("store: write diff state: %w", err)
		}
		for _, o := range res.Observations {
			_, err := tx.ExecContext(ctx, `INSERT INTO observations (watch_id, check_name, observed_at, is_baseline, data, hash)
				VALUES (?, ?, ?, ?, ?, ?)`, watchID, o.Check, formatTime(o.ObservedAt), res.Baseline, string(o.Data), o.Hash)
			if err != nil {
				return fmt.Errorf("store: insert observation: %w", err)
			}
		}
		for i, e := range res.Events {
			e.WatchID = watchID
			var sinks []string
			if i < len(res.Routes) {
				sinks = res.Routes[i]
			}
			if e, err = insertEvent(ctx, tx, e, sinks); err != nil {
				return err
			}
			stored = append(stored, e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// Reschedule sets the next check time without storing anything, for
// example after a failed check.
func (s *Store) Reschedule(ctx context.Context, watchID int64, next time.Time) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		if err := watchExists(ctx, tx, watchID); err != nil {
			return err
		}
		return setNextCheck(ctx, tx, watchID, next)
	})
}

func watchExists(ctx context.Context, tx *sql.Tx, id int64) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM watches WHERE id = ?`, id).Scan(&one)
	if err == sql.ErrNoRows {
		return fmt.Errorf("watch %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("store: look up watch %d: %w", id, err)
	}
	return nil
}

func setNextCheck(ctx context.Context, tx *sql.Tx, id int64, next time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE watches SET next_check_at = ? WHERE id = ?`, formatTime(next), id); err != nil {
		return fmt.Errorf("store: set next check: %w", err)
	}
	return nil
}

// TimelineEntry is one observation or event in a watch's history.
type TimelineEntry struct {
	Kind     string          `json:"kind"` // observation | event
	ID       int64           `json:"id"`
	At       time.Time       `json:"at"`
	Check    string          `json:"check,omitempty"`    // observations
	Hash     string          `json:"hash,omitempty"`     // observations
	Baseline bool            `json:"baseline,omitempty"` // observations
	Type     string          `json:"type,omitempty"`     // events
	Severity string          `json:"severity,omitempty"` // events
	Data     json.RawMessage `json:"data"`               // observation data or event payload
}

// History returns observations and events of a watch at or after since,
// newest first, at most limit entries.
func (s *Store) History(ctx context.Context, domain string, since time.Time, limit int) ([]TimelineEntry, error) {
	w, err := getWatch(ctx, s.r, domain)
	if err != nil {
		return nil, err
	}
	from := ""
	if !since.IsZero() {
		from = formatTime(since)
	}
	rows, err := s.r.QueryContext(ctx, `
		SELECT 'observation', id, observed_at, check_name, hash, is_baseline, '', '', data
		  FROM observations WHERE watch_id = ? AND observed_at >= ?
		UNION ALL
		SELECT 'event', id, occurred_at, '', '', 0, type, severity, payload
		  FROM events WHERE watch_id = ? AND occurred_at >= ?
		ORDER BY 3 DESC, 1, 2 DESC
		LIMIT ?`, w.ID, from, w.ID, from, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query history: %w", err)
	}
	defer rows.Close()
	out := []TimelineEntry{}
	for rows.Next() {
		var (
			e    TimelineEntry
			at   string
			data string
		)
		if err := rows.Scan(&e.Kind, &e.ID, &at, &e.Check, &e.Hash, &e.Baseline, &e.Type, &e.Severity, &data); err != nil {
			return nil, fmt.Errorf("store: scan history: %w", err)
		}
		if e.At, err = parseTime(at); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query history: %w", err)
	}
	return out, nil
}
