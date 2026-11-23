package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID      int64           `json:"id"`
	At      time.Time       `json:"at"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	WatchID int64           `json:"watch_id,omitempty"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

func audit(ctx context.Context, tx *sql.Tx, at time.Time, actor, action string, watchID int64, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("store: encode audit detail: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, watch_id, detail) VALUES (?, ?, ?, ?, ?)`,
		formatTime(at), actor, action, watchID, string(b))
	if err != nil {
		return fmt.Errorf("store: write audit log: %w", err)
	}
	return nil
}

// AuditLog returns the newest entries first, at most limit.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, at, actor, action, COALESCE(watch_id, 0), COALESCE(detail, '')
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: query audit log: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e      AuditEntry
			at     string
			detail string
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.WatchID, &detail); err != nil {
			return nil, fmt.Errorf("store: scan audit log: %w", err)
		}
		if e.At, err = parseTime(at); err != nil {
			return nil, err
		}
		if detail != "" {
			e.Detail = json.RawMessage(detail)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query audit log: %w", err)
	}
	return out, nil
}
