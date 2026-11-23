package events

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"
)

type fakeOutbox struct {
	mu   sync.Mutex
	rows map[string]*fakeRow // key "id/sink"
}

type fakeRow struct {
	d         Delivery
	delivered bool
	next      time.Time
	lastErr   string
}

func (f *fakeOutbox) add(e Event, sinks ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range sinks {
		f.rows[key(e.ID, s)] = &fakeRow{d: Delivery{Event: e, Sink: s}, next: e.OccurredAt}
	}
}

func key(id int64, sink string) string { return string(rune('0'+id)) + "/" + sink }

func (f *fakeOutbox) DueDeliveries(_ context.Context, now time.Time, limit int) ([]Delivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Delivery
	for _, r := range f.rows {
		if !r.delivered && !r.next.After(now) {
			out = append(out, r.d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Event.ID != out[j].Event.ID {
			return out[i].Event.ID < out[j].Event.ID
		}
		return out[i].Sink < out[j].Sink
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeOutbox) MarkDelivered(_ context.Context, id int64, sink string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[key(id, sink)]
	r.delivered = true
	r.d.Attempts++
	return nil
}

func (f *fakeOutbox) MarkFailed(_ context.Context, id int64, sink, msg string, next time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[key(id, sink)]
	r.d.Attempts++
	r.next = next
	r.lastErr = msg
	return nil
}

type fakeSink struct {
	name string
	mu   sync.Mutex
	err  error
	got  []int64
}

func (s *fakeSink) Name() string          { return s.name }
func (s *fakeSink) MinSeverity() Severity { return Info }
func (s *fakeSink) Deliver(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.got = append(s.got, e.ID)
	return nil
}

func (s *fakeSink) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func TestDispatcherRetriesUntilDelivered(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	ob := &fakeOutbox{rows: map[string]*fakeRow{}}
	discord := &fakeSink{name: "discord"}
	hook := &fakeSink{name: "webhook"}
	d := NewDispatcher(DispatcherConfig{
		Store: ob, Sinks: []Sink{discord, hook}, Log: slog.New(slog.DiscardHandler),
		Now: c.Now, Rand: func() float64 { return 0.5 },
	})
	for id := int64(1); id <= 3; id++ {
		ob.add(Event{ID: id, OccurredAt: c.Now()}, "discord", "webhook")
	}
	ob.add(Event{ID: 4, OccurredAt: c.Now()}, "removed-sink")

	discord.setErr(errors.New("HTTP 503"))
	if _, err := d.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(hook.got) != 3 || len(discord.got) != 0 {
		t.Fatalf("round 1: webhook %v discord %v", hook.got, discord.got)
	}
	r := ob.rows[key(1, "discord")]
	if r.d.Attempts != 1 || r.lastErr != "HTTP 503" || !r.next.Equal(c.Now().Add(31*time.Second)) {
		t.Errorf("first failure: %+v", r)
	}
	if ob.rows[key(2, "discord")].d.Attempts != 0 {
		t.Error("a down sink was tried again in the same round")
	}

	// Outage continues: backoff doubles.
	c.Advance(31 * time.Second)
	d.RunOnce(t.Context())
	if r := ob.rows[key(1, "discord")]; r.d.Attempts != 2 || !r.next.Equal(c.Now().Add(61*time.Second)) {
		t.Errorf("second failure: %+v", r)
	}

	// Sink recovers: everything pending is delivered in order.
	discord.setErr(nil)
	c.Advance(time.Hour)
	d.RunOnce(t.Context())
	if len(discord.got) != 3 || discord.got[0] != 1 || discord.got[2] != 3 {
		t.Errorf("after recovery discord got %v", discord.got)
	}
	if r := ob.rows[key(4, "removed-sink")]; r.delivered || r.lastErr != "sink is not configured" {
		t.Errorf("unknown sink row: %+v", r)
	}
}

func TestBackoff(t *testing.T) {
	d := NewDispatcher(DispatcherConfig{Log: slog.New(slog.DiscardHandler), Rand: func() float64 { return 0.5 }})
	tests := []struct {
		attempt int
		err     error
		want    time.Duration
	}{
		{1, errors.New("x"), 31 * time.Second},
		{2, errors.New("x"), 61 * time.Second},
		{3, errors.New("x"), 121 * time.Second},
		{20, errors.New("x"), time.Hour + time.Second},
		{1, &RetryAfterError{After: 5 * time.Minute, Err: errors.New("429")}, 5*time.Minute + time.Second},
	}
	for _, tt := range tests {
		if got := d.backoff(tt.attempt, tt.err); got != tt.want {
			t.Errorf("backoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestDispatcherNotifyAndStop(t *testing.T) {
	ob := &fakeOutbox{rows: map[string]*fakeRow{}}
	hook := &fakeSink{name: "webhook"}
	d := NewDispatcher(DispatcherConfig{Store: ob, Sinks: []Sink{hook}, Log: slog.New(slog.DiscardHandler), Tick: time.Hour})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	time.Sleep(20 * time.Millisecond) // first round finds nothing, then waits a tick
	ob.add(Event{ID: 1, OccurredAt: time.Now().Add(-time.Second)}, "webhook")
	d.Notify()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hook.mu.Lock()
		n := len(hook.got)
		hook.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Notify did not trigger a round")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
