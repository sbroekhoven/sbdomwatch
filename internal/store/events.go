package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

// insertEvent stores e and one outbox row per sink, all due at once.
func insertEvent(ctx context.Context, tx *sql.Tx, e events.Event, sinks []string) (events.Event, error) {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return e, fmt.Errorf("store: encode event: %w", err)
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO events (watch_id, type, severity, occurred_at, payload)
		VALUES (?, ?, ?, ?, ?) RETURNING id`, e.WatchID, e.Type, e.Severity, formatTime(e.OccurredAt), string(payload)).Scan(&e.ID)
	if err != nil {
		return e, fmt.Errorf("store: insert event: %w", err)
	}
	for _, sink := range sinks {
		_, err := tx.ExecContext(ctx, `INSERT INTO event_deliveries (event_id, sink, attempts, next_attempt_at)
			VALUES (?, ?, 0, ?) ON CONFLICT (event_id, sink) DO NOTHING`, e.ID, sink, formatTime(e.OccurredAt))
		if err != nil {
			return e, fmt.Errorf("store: enqueue event %d for %s: %w", e.ID, sink, err)
		}
	}
	return e, nil
}

const selectEvent = `SELECT e.id, e.watch_id, e.type, e.severity, e.occurred_at, e.payload FROM events e`

func scanEvent(rows *sql.Rows, extra ...any) (events.Event, error) {
	var (
		e       events.Event
		at      string
		payload string
	)
	dest := append([]any{&e.ID, &e.WatchID, &e.Type, &e.Severity, &at, &payload}, extra...)
	if err := rows.Scan(dest...); err != nil {
		return e, fmt.Errorf("store: scan event: %w", err)
	}
	t, err := parseTime(at)
	if err != nil {
		return e, err
	}
	e.OccurredAt = t
	if err := json.Unmarshal([]byte(payload), &e.Payload); err != nil {
		return e, fmt.Errorf("store: decode event %d: %w", e.ID, err)
	}
	return e, nil
}

// EventFilter selects events for ListEvents.
type EventFilter struct {
	Since       time.Time
	Types       []events.Type
	Domain      string          // normalized
	MinSeverity events.Severity // empty: all
	Limit       int
}

// ListEvents returns events newest first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]events.Event, error) {
	var where []string
	var args []any
	if !f.Since.IsZero() {
		where = append(where, "e.occurred_at >= ?")
		args = append(args, formatTime(f.Since))
	}
	if len(f.Types) > 0 {
		b, _ := json.Marshal(f.Types)
		where = append(where, "e.type IN (SELECT value FROM json_each(?))")
		args = append(args, string(b))
	}
	if f.Domain != "" {
		where = append(where, "e.watch_id = (SELECT id FROM watches WHERE domain = ?)")
		args = append(args, f.Domain)
	}
	if f.MinSeverity != "" {
		b, _ := json.Marshal(events.AtLeast(f.MinSeverity))
		where = append(where, "e.severity IN (SELECT value FROM json_each(?))")
		args = append(args, string(b))
	}
	q := selectEvent
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY e.occurred_at DESC, e.id DESC LIMIT ?"
	args = append(args, max(f.Limit, 1))
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()
	out := []events.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query events: %w", err)
	}
	return out, nil
}

// DueDeliveries returns undelivered outbox rows whose next attempt is due,
// oldest event first.
func (s *Store) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]events.Delivery, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT e.id, e.watch_id, e.type, e.severity, e.occurred_at, e.payload, d.sink, d.attempts
		FROM event_deliveries d JOIN events e ON e.id = d.event_id
		WHERE d.delivered_at IS NULL AND d.next_attempt_at <= ?
		ORDER BY e.id, d.sink LIMIT ?`, formatTime(now), limit)
	if err != nil {
		return nil, fmt.Errorf("store: query deliveries: %w", err)
	}
	defer rows.Close()
	var out []events.Delivery
	for rows.Next() {
		var d events.Delivery
		e, err := scanEvent(rows, &d.Sink, &d.Attempts)
		if err != nil {
			return nil, err
		}
		d.Event = e
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query deliveries: %w", err)
	}
	return out, nil
}

// MarkDelivered records a successful delivery.
func (s *Store) MarkDelivered(ctx context.Context, eventID int64, sink string, at time.Time) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET delivered_at = ?, attempts = attempts + 1, last_error = NULL
			WHERE event_id = ? AND sink = ?`, formatTime(at), eventID, sink)
		if err != nil {
			return fmt.Errorf("store: mark delivered: %w", err)
		}
		return nil
	})
}

// MarkFailed records a failed attempt and when to try again. msg must not
// contain secrets such as webhook URLs.
func (s *Store) MarkFailed(ctx context.Context, eventID int64, sink, msg string, next time.Time) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE event_deliveries SET attempts = attempts + 1, last_error = ?, next_attempt_at = ?
			WHERE event_id = ? AND sink = ?`, msg, formatTime(next), eventID, sink)
		if err != nil {
			return fmt.Errorf("store: mark failed: %w", err)
		}
		return nil
	})
}

// OutboxStats counts undelivered outbox rows per sink.
func (s *Store) OutboxStats(ctx context.Context) (map[string]int, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT sink, COUNT(*) FROM event_deliveries WHERE delivered_at IS NULL GROUP BY sink`)
	if err != nil {
		return nil, fmt.Errorf("store: outbox stats: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sink string
		var n int
		if err := rows.Scan(&sink, &n); err != nil {
			return nil, fmt.Errorf("store: outbox stats: %w", err)
		}
		out[sink] = n
	}
	return out, rows.Err()
}
