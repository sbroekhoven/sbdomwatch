package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var defaults = watch.Defaults{
	Intervals: map[watch.Template]time.Duration{
		watch.TemplateOwned:      time.Hour,
		watch.TemplateCandidate:  6 * time.Hour,
		watch.TemplateThirdParty: 6 * time.Hour,
	},
	CandidateTTL: 90 * 24 * time.Hour,
}

func newStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "test.db"), Options{Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, clock
}

func add(t *testing.T, s *Store, r watch.AddRequest) AddResult {
	t.Helper()
	n, err := r.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.AddWatch(t.Context(), n, "seb", defaults)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestOpenPragmasAndMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	s, err := Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	var fk, busy int
	if err := s.w.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v", mode, err)
	}
	if err := s.r.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d, %v", fk, err)
	}
	if err := s.r.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil || busy != 5000 {
		t.Errorf("busy_timeout = %d, %v", busy, err)
	}
	if _, err := s.r.Exec(`INSERT INTO audit_log (at, actor, action) VALUES ('x','y','z')`); err == nil {
		t.Error("reader pool accepted a write")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopening applies nothing new and works.
	s, err = Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.r.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 3 {
		t.Errorf("schema_migrations rows = %d, %v", n, err)
	}
	s.Close()
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	s, err := Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO schema_migrations VALUES (99, 'x')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(t.Context(), path, Options{}); err == nil {
		t.Fatal("want error for newer schema")
	}
}

func TestAddWatchMergesAndNormalizes(t *testing.T) {
	s, clock := newStore(t)
	ctx := t.Context()

	r1 := add(t, s, watch.AddRequest{Domain: "Degiro.NL.", Template: watch.TemplateOwned, Reason: "company domain"})
	if !r1.Created || r1.Watch.Domain != "degiro.nl" || r1.Watch.ID == 0 {
		t.Fatalf("first add: %+v", r1)
	}
	clock.Advance(time.Minute)
	r2 := add(t, s, watch.AddRequest{Domain: "degiro.nl", Template: watch.TemplateOwned, Reason: "incident 42", Origin: watch.OriginIncident, Reference: "INC-42", Tags: map[string]string{"team": "sec"}})
	if r2.Created || !r2.Changed || r2.Watch.ID != r1.Watch.ID {
		t.Fatalf("second add: %+v", r2)
	}
	r3 := add(t, s, watch.AddRequest{Domain: "DEGIRO.nl", Template: watch.TemplateOwned, Reason: "company domain"})
	if r3.Created || r3.Changed {
		t.Fatalf("repeat add should be a no-op: %+v", r3)
	}

	got, err := s.GetWatch(ctx, "degiro.nl")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Origins) != 2 || got.Origins[1].Reference != "INC-42" || got.Origins[1].Origin != watch.OriginIncident {
		t.Errorf("origins = %+v", got.Origins)
	}
	if got.Tags["team"] != "sec" || !got.UpdatedAt.Equal(clock.Now()) || got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("watch = %+v", got)
	}

	all, err := s.ListWatches(ctx, Filter{All: true})
	if err != nil || len(all) != 1 {
		t.Fatalf("want exactly one watch, got %d, %v", len(all), err)
	}

	idn := add(t, s, watch.AddRequest{Domain: "bücher.de", Template: watch.TemplateCandidate, Reason: "idn test"})
	if idn.Watch.Domain != "xn--bcher-kva.de" {
		t.Errorf("idn stored as %q", idn.Watch.Domain)
	}

	log, err := s.AuditLog(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Action)
	}
	want := []string{"watch.add", "watch.merge", "watch.add"}
	if len(actions) != 3 || actions[0] != want[0] || actions[1] != want[1] || actions[2] != want[2] {
		t.Errorf("audit actions (newest first) = %v", actions)
	}
}

func TestEmptyReasonRejectedByDatabase(t *testing.T) {
	s, _ := newStore(t)
	// Bypass validation to prove the CHECK constraint is a second line of defence.
	_, err := s.AddWatch(t.Context(), watch.AddRequest{Domain: "example.com", Template: watch.TemplateOwned, Origin: watch.OriginManual}, "seb", defaults)
	if err == nil {
		t.Fatal("empty reason was stored")
	}
	if ws, _ := s.ListWatches(t.Context(), Filter{All: true}); len(ws) != 0 {
		t.Errorf("failed add left %d watches behind", len(ws))
	}
}

func TestAddWatchesIsAtomic(t *testing.T) {
	s, _ := newStore(t)
	good, _ := watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x"}.Normalize()
	bad := watch.AddRequest{Domain: "b.com", Template: watch.TemplateOwned, Origin: watch.OriginManual} // empty reason
	if _, err := s.AddWatches(t.Context(), []watch.AddRequest{good, bad}, "seb", defaults); err == nil {
		t.Fatal("want error")
	}
	if ws, _ := s.ListWatches(t.Context(), Filter{All: true}); len(ws) != 0 {
		t.Errorf("partial bulk add stored %d watches", len(ws))
	}
}

func TestListWatchesFilters(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	add(t, s, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x", Tags: map[string]string{"profile": "degiro"}})
	add(t, s, watch.AddRequest{Domain: "b.com", Template: watch.TemplateCandidate, Reason: "x", Origin: watch.OriginTyposquat, Tags: map[string]string{"profile": "other"}})
	add(t, s, watch.AddRequest{Domain: "c.com", Template: watch.TemplateCandidate, Reason: "x"})
	if _, err := s.ArchiveWatch(ctx, "c.com", "seb"); err != nil {
		t.Fatal(err)
	}
	yes := true
	if _, err := s.PatchWatch(ctx, "a.com", watch.PatchRequest{Paused: &yes}, "seb"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		f    Filter
		want []string
	}{
		{"default hides archived", Filter{}, []string{"a.com", "b.com"}},
		{"all", Filter{All: true}, []string{"a.com", "b.com", "c.com"}},
		{"state archived", Filter{State: watch.StateArchived}, []string{"c.com"}},
		{"state paused", Filter{State: watch.StatePaused}, []string{"a.com"}},
		{"tag", Filter{TagKey: "profile", TagVal: "degiro"}, []string{"a.com"}},
		{"tag no match", Filter{TagKey: "profile", TagVal: "nope"}, nil},
		{"origin", Filter{Origin: watch.OriginTyposquat}, []string{"b.com"}},
		{"domains", Filter{All: true, Domains: []string{"c.com", "a.com"}}, []string{"a.com", "c.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := s.ListWatches(ctx, tt.f)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, w := range ws {
				got = append(got, w.Domain)
				if len(w.Origins) == 0 {
					t.Errorf("%s listed without origins", w.Domain)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestPatchArchiveDelete(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	add(t, s, watch.AddRequest{Domain: "example.com", Template: watch.TemplateOwned, Reason: "x"})

	yes, no := true, false
	w, err := s.PatchWatch(ctx, "example.com", watch.PatchRequest{Paused: &yes}, "seb")
	if err != nil || w.State != watch.StatePaused {
		t.Fatalf("pause: %+v, %v", w, err)
	}
	w, err = s.PatchWatch(ctx, "example.com", watch.PatchRequest{Paused: &no}, "seb")
	if err != nil || w.State != watch.StateNew {
		t.Fatalf("resume: %+v, %v", w, err)
	}
	w, err = s.ArchiveWatch(ctx, "example.com", "seb")
	if err != nil || w.State != watch.StateArchived {
		t.Fatalf("archive: %+v, %v", w, err)
	}
	if _, err := s.PatchWatch(ctx, "example.com", watch.PatchRequest{Paused: &yes}, "seb"); !errors.Is(err, watch.ErrArchived) {
		t.Fatalf("patch archived: err = %v", err)
	}
	if err := s.DeleteWatch(ctx, "example.com", "seb"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWatch(ctx, "example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	for _, fn := range []func() error{
		func() error { _, err := s.ArchiveWatch(ctx, "nope.com", "seb"); return err },
		func() error { _, err := s.PatchWatch(ctx, "nope.com", watch.PatchRequest{}, "seb"); return err },
		func() error { return s.DeleteWatch(ctx, "nope.com", "seb") },
	} {
		if err := fn(); !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	}
	log, _ := s.AuditLog(ctx, 1)
	if len(log) != 1 || log[0].Action != "watch.delete" {
		t.Errorf("last audit entry = %+v", log)
	}
}

func TestConcurrentAdds(t *testing.T) {
	s, _ := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	r, _ := watch.AddRequest{Domain: "example.com", Template: watch.TemplateCandidate, Reason: "x"}.Normalize()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := r
			req.Tags = map[string]string{"n": string(rune('a' + i))}
			if _, err := s.AddWatch(ctx, req, "seb", defaults); err != nil {
				errs <- err
			}
			if _, err := s.ListWatches(ctx, Filter{}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	ws, _ := s.ListWatches(ctx, Filter{})
	if len(ws) != 1 {
		t.Errorf("got %d watches, want 1", len(ws))
	}
}
