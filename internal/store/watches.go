package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// AddResult is the outcome of adding one watch.
type AddResult struct {
	Watch   watch.Watch `json:"watch"`
	Created bool        `json:"created"`
	Changed bool        `json:"changed"`
}

// AddWatch adds or merges one watch. req must be normalized.
func (s *Store) AddWatch(ctx context.Context, req watch.AddRequest, actor string, d watch.Defaults) (AddResult, error) {
	res, err := s.AddWatches(ctx, []watch.AddRequest{req}, actor, d)
	if err != nil {
		return AddResult{}, err
	}
	return res[0], nil
}

// AddWatches adds or merges several watches in one transaction: either all
// are stored or none. Every request must be normalized.
func (s *Store) AddWatches(ctx context.Context, reqs []watch.AddRequest, actor string, d watch.Defaults) ([]AddResult, error) {
	results := make([]AddResult, 0, len(reqs))
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		now := s.now()
		for _, req := range reqs {
			existing, err := getWatch(ctx, tx, req.Domain)
			var cur *watch.Watch
			switch {
			case err == nil:
				cur = &existing
			case !errors.Is(err, ErrNotFound):
				return err
			}
			w, created, changed := watch.Apply(cur, req, actor, now, d)
			if changed {
				if w, err = saveWatch(ctx, tx, w); err != nil {
					return err
				}
				action := "watch.merge"
				if created {
					action = "watch.add"
				}
				detail := map[string]any{"domain": w.Domain, "template": w.Template, "origin": req.Origin, "reason": req.Reason}
				if req.Reference != "" {
					detail["reference"] = req.Reference
				}
				if err := audit(ctx, tx, now, actor, action, w.ID, detail); err != nil {
					return err
				}
			}
			results = append(results, AddResult{Watch: w, Created: created, Changed: changed})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// GetWatch returns one watch with its origins.
func (s *Store) GetWatch(ctx context.Context, domain string) (watch.Watch, error) {
	return getWatch(ctx, s.r, domain)
}

// Filter selects watches for ListWatches.
type Filter struct {
	State   watch.State      // empty: every state except archived
	All     bool             // include archived when State is empty
	TagKey  string           // with TagValue: tags[TagKey] == TagValue
	TagVal  string           //
	Origin  watch.OriginKind // has at least one origin of this kind
	Domains []string         // restrict to these domains
}

// ListWatches returns watches ordered by domain.
func (s *Store) ListWatches(ctx context.Context, f Filter) ([]watch.Watch, error) {
	var where []string
	var args []any
	switch {
	case f.State != "":
		where = append(where, "w.state = ?")
		args = append(args, string(f.State))
	case !f.All:
		where = append(where, "w.state <> ?")
		args = append(args, string(watch.StateArchived))
	}
	if f.TagKey != "" {
		// The key is validated by the caller; it is passed as a JSON path parameter.
		where = append(where, "json_extract(w.tags, ?) = ?")
		args = append(args, `$."`+f.TagKey+`"`, f.TagVal)
	}
	if f.Origin != "" {
		where = append(where, "EXISTS (SELECT 1 FROM watch_origins o WHERE o.watch_id = w.id AND o.origin = ?)")
		args = append(args, string(f.Origin))
	}
	if len(f.Domains) > 0 {
		b, _ := json.Marshal(f.Domains)
		where = append(where, "w.domain IN (SELECT value FROM json_each(?))")
		args = append(args, string(b))
	}
	q := selectWatch
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY w.domain"
	return queryWatches(ctx, s.r, q, args...)
}

// PatchWatch changes a watch. p must be validated.
func (s *Store) PatchWatch(ctx context.Context, domain string, p watch.PatchRequest, actor string) (watch.Watch, error) {
	var out watch.Watch
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		cur, err := getWatch(ctx, tx, domain)
		if err != nil {
			return err
		}
		now := s.now()
		w, changed, err := watch.ApplyPatch(cur, p, now)
		if err != nil {
			return err
		}
		out = w
		if !changed {
			return nil
		}
		if out, err = saveWatch(ctx, tx, w); err != nil {
			return err
		}
		detail := map[string]any{"domain": w.Domain, "from_state": cur.State, "to_state": w.State, "patch": p}
		return audit(ctx, tx, now, actor, "watch.update", w.ID, detail)
	})
	return out, err
}

// ArchiveWatch stops checks on a watch and keeps its history.
func (s *Store) ArchiveWatch(ctx context.Context, domain, actor string) (watch.Watch, error) {
	var out watch.Watch
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		cur, err := getWatch(ctx, tx, domain)
		if err != nil {
			return err
		}
		now := s.now()
		w, changed := watch.Archive(cur, now)
		out = w
		if !changed {
			return nil
		}
		if out, err = saveWatch(ctx, tx, w); err != nil {
			return err
		}
		return audit(ctx, tx, now, actor, "watch.archive", w.ID, map[string]any{"domain": w.Domain, "from_state": cur.State})
	})
	return out, err
}

// DeleteWatch removes a watch and everything recorded about it. The audit
// log keeps a record of the deletion.
func (s *Store) DeleteWatch(ctx context.Context, domain, actor string) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		cur, err := getWatch(ctx, tx, domain)
		if err != nil {
			return err
		}
		stmts := []string{
			`DELETE FROM event_deliveries WHERE event_id IN (SELECT id FROM events WHERE watch_id = ?)`,
			`DELETE FROM events WHERE watch_id = ?`,
			`DELETE FROM observations WHERE watch_id = ?`,
			`DELETE FROM watch_origins WHERE watch_id = ?`,
			`DELETE FROM watches WHERE id = ?`,
		}
		for _, q := range stmts {
			if _, err := tx.ExecContext(ctx, q, cur.ID); err != nil {
				return fmt.Errorf("store: delete watch: %w", err)
			}
		}
		return audit(ctx, tx, s.now(), actor, "watch.delete", cur.ID, map[string]any{"domain": cur.Domain, "origins": cur.Origins})
	})
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const selectWatch = `SELECT w.id, w.domain, w.template, w.state, w.interval_sec, w.next_check_at,
	w.baseline_started_at, w.baseline_completed_at, w.volatile_fields, w.tags, w.expires_at,
	w.created_at, w.updated_at
	FROM watches w`

func getWatch(ctx context.Context, q querier, domain string) (watch.Watch, error) {
	ws, err := queryWatches(ctx, q, selectWatch+" WHERE w.domain = ?", domain)
	if err != nil {
		return watch.Watch{}, err
	}
	if len(ws) == 0 {
		return watch.Watch{}, fmt.Errorf("watch %s: %w", domain, ErrNotFound)
	}
	return ws[0], nil
}

func queryWatches(ctx context.Context, q querier, query string, args ...any) ([]watch.Watch, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query watches: %w", err)
	}
	var ws []watch.Watch
	byID := map[int64]int{}
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		byID[w.ID] = len(ws)
		ws = append(ws, w)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: query watches: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query watches: %w", err)
	}
	if len(ws) == 0 {
		return ws, nil
	}

	ids := make([]int64, 0, len(ws))
	for _, w := range ws {
		ids = append(ids, w.ID)
	}
	idJSON, _ := json.Marshal(ids)
	orows, err := q.QueryContext(ctx, `SELECT watch_id, origin, reason, reference, added_by, added_at
		FROM watch_origins WHERE watch_id IN (SELECT value FROM json_each(?))
		ORDER BY added_at, rowid`, string(idJSON))
	if err != nil {
		return nil, fmt.Errorf("store: query origins: %w", err)
	}
	defer orows.Close()
	for orows.Next() {
		var (
			id      int64
			o       watch.Origin
			ref     sql.NullString
			addedAt string
		)
		if err := orows.Scan(&id, &o.Origin, &o.Reason, &ref, &o.AddedBy, &addedAt); err != nil {
			return nil, fmt.Errorf("store: scan origin: %w", err)
		}
		o.Reference = ref.String
		if o.AddedAt, err = parseTime(addedAt); err != nil {
			return nil, err
		}
		i := byID[id]
		ws[i].Origins = append(ws[i].Origins, o)
	}
	if err := orows.Err(); err != nil {
		return nil, fmt.Errorf("store: query origins: %w", err)
	}
	return ws, nil
}

func scanWatch(rows *sql.Rows) (watch.Watch, error) {
	var (
		w                            watch.Watch
		next, created, updated       string
		baseStart, baseDone, expires sql.NullString
		volatileJSON, tagsJSON       string
	)
	err := rows.Scan(&w.ID, &w.Domain, &w.Template, &w.State, &w.IntervalSec, &next,
		&baseStart, &baseDone, &volatileJSON, &tagsJSON, &expires, &created, &updated)
	if err != nil {
		return w, fmt.Errorf("store: scan watch: %w", err)
	}
	var errs []error
	var e error
	w.NextCheckAt, e = parseTime(next)
	errs = append(errs, e)
	w.CreatedAt, e = parseTime(created)
	errs = append(errs, e)
	w.UpdatedAt, e = parseTime(updated)
	errs = append(errs, e)
	w.BaselineStartedAt, e = parseTimePtr(baseStart)
	errs = append(errs, e)
	w.BaselineCompletedAt, e = parseTimePtr(baseDone)
	errs = append(errs, e)
	w.ExpiresAt, e = parseTimePtr(expires)
	errs = append(errs, e)
	if e := json.Unmarshal([]byte(volatileJSON), &w.VolatileFields); e != nil {
		errs = append(errs, fmt.Errorf("store: volatile_fields of %s: %w", w.Domain, e))
	}
	if e := json.Unmarshal([]byte(tagsJSON), &w.Tags); e != nil {
		errs = append(errs, fmt.Errorf("store: tags of %s: %w", w.Domain, e))
	}
	if err := errors.Join(errs...); err != nil {
		return w, err
	}
	if w.Tags == nil {
		w.Tags = map[string]string{}
	}
	if w.VolatileFields == nil {
		w.VolatileFields = []string{}
	}
	w.Origins = []watch.Origin{}
	return w, nil
}

// saveWatch inserts (ID 0) or updates a watch and inserts any new origins.
func saveWatch(ctx context.Context, tx *sql.Tx, w watch.Watch) (watch.Watch, error) {
	tags, err := json.Marshal(w.Tags)
	if err != nil {
		return w, fmt.Errorf("store: encode tags: %w", err)
	}
	volatile, err := json.Marshal(w.VolatileFields)
	if err != nil {
		return w, fmt.Errorf("store: encode volatile_fields: %w", err)
	}
	args := []any{w.Template, w.State, w.IntervalSec, formatTime(w.NextCheckAt),
		formatTimePtr(w.BaselineStartedAt), formatTimePtr(w.BaselineCompletedAt),
		string(volatile), string(tags), formatTimePtr(w.ExpiresAt), formatTime(w.UpdatedAt)}
	if w.ID == 0 {
		err = tx.QueryRowContext(ctx, `INSERT INTO watches (template, state, interval_sec, next_check_at,
			baseline_started_at, baseline_completed_at, volatile_fields, tags, expires_at, updated_at,
			domain, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			append(args, w.Domain, formatTime(w.CreatedAt))...).Scan(&w.ID)
		if err != nil {
			return w, fmt.Errorf("store: insert watch %s: %w", w.Domain, err)
		}
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE watches SET template = ?, state = ?, interval_sec = ?,
			next_check_at = ?, baseline_started_at = ?, baseline_completed_at = ?, volatile_fields = ?,
			tags = ?, expires_at = ?, updated_at = ? WHERE id = ?`, append(args, w.ID)...)
		if err != nil {
			return w, fmt.Errorf("store: update watch %s: %w", w.Domain, err)
		}
	}
	for _, o := range w.Origins {
		var ref any
		if o.Reference != "" {
			ref = o.Reference
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO watch_origins
			(watch_id, origin, reason, reference, added_by, added_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (watch_id, origin, reason) DO NOTHING`,
			w.ID, o.Origin, o.Reason, ref, o.AddedBy, formatTime(o.AddedAt))
		if err != nil {
			return w, fmt.Errorf("store: insert origin for %s: %w", w.Domain, err)
		}
	}
	return w, nil
}
