package sched

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

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

// fakeCheck records which domains it saw and can be told to fail.
type fakeCheck struct {
	name  string
	now   func() time.Time
	fail  map[string]bool
	mu    sync.Mutex
	seen  map[string]int
	delay time.Duration
	busy  atomic.Int32
	peak  atomic.Int32
}

func (f *fakeCheck) Name() string { return f.name }

func (f *fakeCheck) Run(ctx context.Context, domain string) (check.Observation, error) {
	n := f.busy.Add(1)
	defer f.busy.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return check.Observation{}, ctx.Err()
		}
	}
	f.mu.Lock()
	f.seen[domain]++
	f.mu.Unlock()
	if f.fail[domain] {
		return check.Observation{}, errors.New("simulated failure")
	}
	return check.NewObservation(f.name, f.now(), map[string]string{"domain": domain})
}

func (f *fakeCheck) count(domain string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[domain]
}

type env struct {
	st    *store.Store
	clock *fakeClock
	dns   *fakeCheck
	rdap  *fakeCheck
	s     *Scheduler
}

func newEnv(t *testing.T, workers int) *env {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "s.db"), store.Options{Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{
		st:    st,
		clock: clock,
		dns:   &fakeCheck{name: "dns", now: clock.Now, fail: map[string]bool{}, seen: map[string]int{}},
		rdap:  &fakeCheck{name: "rdap", now: clock.Now, fail: map[string]bool{}, seen: map[string]int{}},
	}
	e.s = New(Config{
		Store:     st,
		Checks:    []check.Check{e.dns, e.rdap},
		Log:       slog.New(slog.DiscardHandler),
		Workers:   workers,
		Lifecycle: watch.LifecycleConfig{BaselineObservations: 1, Debounce: 2},
		Now:       clock.Now,
		Rand:      func() float64 { return 0.5 }, // no jitter
	})
	return e
}

func (e *env) add(t *testing.T, domain string, interval time.Duration) {
	t.Helper()
	r, err := watch.AddRequest{Domain: domain, Template: watch.TemplateOwned, Reason: "test", IntervalSec: int(interval / time.Second)}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	d := watch.Defaults{Intervals: map[watch.Template]time.Duration{watch.TemplateOwned: time.Hour}}
	if _, err := e.st.AddWatch(t.Context(), r, "seb", d); err != nil {
		t.Fatal(err)
	}
}

func (e *env) runOnce(t *testing.T) int {
	t.Helper()
	n, err := e.s.RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// history returns the observations of domain, newest first.
func (e *env) history(t *testing.T, domain string) []store.TimelineEntry {
	t.Helper()
	return e.timeline(t, domain, "observation")
}

// timeline returns entries of one kind, newest first.
func (e *env) timeline(t *testing.T, domain, kind string) []store.TimelineEntry {
	t.Helper()
	h, err := e.st.History(t.Context(), domain, time.Time{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.TimelineEntry
	for _, x := range h {
		if x.Kind == kind {
			out = append(out, x)
		}
	}
	return out
}

func TestObservedOnSchedule(t *testing.T) {
	e := newEnv(t, 2)
	e.add(t, "example.com", time.Hour)

	steps := []struct {
		advance      time.Duration
		wantClaimed  int
		wantObserved int // total observations stored so far (2 checks per round)
	}{
		{0, 1, 2},                // new watch is due immediately
		{0, 0, 2},                // not due again right away
		{59 * time.Minute, 0, 2}, // still before the interval
		{time.Minute, 1, 4},      // due after exactly one interval
		{30 * time.Minute, 0, 4}, //
		{30 * time.Minute, 1, 6}, //
	}
	for i, s := range steps {
		e.clock.Advance(s.advance)
		if got := e.runOnce(t); got != s.wantClaimed {
			t.Fatalf("step %d: claimed %d, want %d", i, got, s.wantClaimed)
		}
		if got := len(e.history(t, "example.com")); got != s.wantObserved {
			t.Fatalf("step %d: %d observations, want %d", i, got, s.wantObserved)
		}
	}
	w, _ := e.st.GetWatch(t.Context(), "example.com")
	if want := e.clock.Now().Add(time.Hour); !w.NextCheckAt.Equal(want) {
		t.Errorf("next_check_at = %v, want %v", w.NextCheckAt, want)
	}
}

func TestPausedAndArchivedAreNotChecked(t *testing.T) {
	e := newEnv(t, 2)
	e.add(t, "paused.com", time.Hour)
	e.add(t, "archived.com", time.Hour)
	yes := true
	if _, err := e.st.PatchWatch(t.Context(), "paused.com", watch.PatchRequest{Paused: &yes}, "seb"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.ArchiveWatch(t.Context(), "archived.com", "seb"); err != nil {
		t.Fatal(err)
	}
	if n := e.runOnce(t); n != 0 {
		t.Fatalf("claimed %d", n)
	}
	if e.dns.count("paused.com")+e.dns.count("archived.com") != 0 {
		t.Error("paused or archived watch was checked")
	}
}

func TestFailures(t *testing.T) {
	e := newEnv(t, 2)
	e.add(t, "partial.com", time.Hour)
	e.add(t, "down.com", time.Hour)
	e.rdap.fail["partial.com"] = true
	e.dns.fail["down.com"] = true
	e.rdap.fail["down.com"] = true

	e.runOnce(t)
	h := e.history(t, "partial.com")
	if len(h) != 1 || h[0].Check != "dns" {
		t.Errorf("partial failure stored %+v, want only the dns observation", h)
	}
	if h := e.history(t, "down.com"); len(h) != 0 {
		t.Errorf("total failure stored %d observations", len(h))
	}
	w, _ := e.st.GetWatch(t.Context(), "down.com")
	if want := e.clock.Now().Add(5 * time.Minute); !w.NextCheckAt.Equal(want) {
		t.Errorf("failed watch next_check_at = %v, want retry at %v", w.NextCheckAt, want)
	}
	w, _ = e.st.GetWatch(t.Context(), "partial.com")
	if want := e.clock.Now().Add(time.Hour); !w.NextCheckAt.Equal(want) {
		t.Errorf("partial watch next_check_at = %v, want %v", w.NextCheckAt, want)
	}

	e.clock.Advance(5 * time.Minute)
	if n := e.runOnce(t); n != 1 || e.dns.count("down.com") != 2 {
		t.Errorf("retry: claimed %d, down.com checked %d times", n, e.dns.count("down.com"))
	}
}

func TestWorkersBoundConcurrency(t *testing.T) {
	e := newEnv(t, 3)
	e.dns.delay = 20 * time.Millisecond
	for i := range 10 {
		e.add(t, string(rune('a'+i))+"x.com", time.Hour)
	}
	if n := e.runOnce(t); n != 10 {
		t.Fatalf("claimed %d", n)
	}
	if p := e.dns.peak.Load(); p > 3 || p < 2 {
		t.Errorf("peak concurrency = %d, want 2..3", p)
	}
	for i := range 10 {
		if e.dns.count(string(rune('a'+i))+"x.com") != 1 {
			t.Errorf("watch %d checked %d times", i, e.dns.count(string(rune('a'+i))+"x.com"))
		}
	}
}

func TestJitter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		r    float64
		want time.Duration
	}{
		{0, 54 * time.Minute},                    // -10%
		{0.5, time.Hour},                         // none
		{0.999999, 66*time.Minute - time.Second}, // just under +10%, truncated
	}
	for _, tt := range tests {
		s := New(Config{Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }, Rand: func() float64 { return tt.r }})
		if got := s.next(time.Hour).Sub(now); got != tt.want {
			t.Errorf("r=%v: next = +%v, want +%v", tt.r, got, tt.want)
		}
	}
}

func TestCancelledCheckRecordsNothing(t *testing.T) {
	e := newEnv(t, 1)
	e.add(t, "slow.com", time.Hour)
	e.dns.delay = time.Minute
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.s.RunOnce(ctx)
	}()
	for e.dns.busy.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if h := e.history(t, "slow.com"); len(h) != 0 {
		t.Errorf("cancelled check stored %d observations", len(h))
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e := newEnv(t, 1)
	e.add(t, "example.com", time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.s.Run(ctx) }()
	for e.dns.count("example.com") == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
