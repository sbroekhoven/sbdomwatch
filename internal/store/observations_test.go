package store

import (
	"errors"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func obs(t *testing.T, at time.Time, v string) check.Observation {
	t.Helper()
	o, err := check.NewObservation("dns", at, map[string]string{"v": v})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestClaimDue(t *testing.T) {
	s, clock := newStore(t)
	ctx := t.Context()
	add(t, s, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x"})
	clock.Advance(time.Second)
	add(t, s, watch.AddRequest{Domain: "b.com", Template: watch.TemplateOwned, Reason: "x"})
	add(t, s, watch.AddRequest{Domain: "c.com", Template: watch.TemplateOwned, Reason: "x"})
	add(t, s, watch.AddRequest{Domain: "paused.com", Template: watch.TemplateOwned, Reason: "x"})
	yes := true
	if _, err := s.PatchWatch(ctx, "paused.com", watch.PatchRequest{Paused: &yes}, "seb"); err != nil {
		t.Fatal(err)
	}
	now := clock.Now()

	due, err := s.ClaimDue(ctx, now, 2, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 || due[0].Domain != "a.com" || due[1].Domain != "b.com" {
		t.Fatalf("first claim = %+v, want a.com then b.com (oldest first)", due)
	}
	if due[0].State != watch.StateNew || due[0].IntervalSec != 3600 {
		t.Errorf("due fields = %+v", due[0])
	}
	due, _ = s.ClaimDue(ctx, now, 10, 10*time.Minute)
	if len(due) != 1 || due[0].Domain != "c.com" {
		t.Fatalf("second claim = %+v, want only c.com (others leased, paused skipped)", due)
	}
	if due, _ = s.ClaimDue(ctx, now.Add(9*time.Minute), 10, 10*time.Minute); len(due) != 0 {
		t.Fatalf("claimed during lease: %+v", due)
	}
	if due, _ = s.ClaimDue(ctx, now.Add(10*time.Minute), 10, 10*time.Minute); len(due) != 3 {
		t.Fatalf("lease expiry: claimed %d, want 3", len(due))
	}
	w, _ := s.GetWatch(ctx, "a.com")
	if !w.UpdatedAt.Equal(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("claiming changed updated_at to %v", w.UpdatedAt)
	}
}

func TestRecordCheckAndHistory(t *testing.T) {
	s, clock := newStore(t)
	ctx := t.Context()
	res := add(t, s, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x"})
	id := res.Watch.ID
	t0 := clock.Now()

	next := t0.Add(time.Hour)
	if err := s.RecordCheck(ctx, id, []check.Observation{obs(t, t0, "1")}, next); err != nil {
		t.Fatal(err)
	}
	w, _ := s.GetWatch(ctx, "a.com")
	if !w.NextCheckAt.Equal(next) {
		t.Errorf("next_check_at = %v, want %v", w.NextCheckAt, next)
	}
	if err := s.RecordCheck(ctx, id, []check.Observation{obs(t, t0.Add(time.Hour), "2")}, next.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO events (watch_id, type, severity, occurred_at, payload) VALUES (?, 'mx_appeared', 'high', ?, '{}')`,
		id, formatTime(t0.Add(30*time.Minute))); err != nil {
		t.Fatal(err)
	}

	h, err := s.History(ctx, "a.com", time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 3 || h[0].Kind != "observation" || h[1].Kind != "event" || h[2].Kind != "observation" {
		t.Fatalf("history = %+v", h)
	}
	if h[1].Type != "mx_appeared" || h[0].Hash == h[2].Hash || string(h[0].Data) != `{"v":"2"}` {
		t.Errorf("entries: %+v", h)
	}
	if h, _ := s.History(ctx, "a.com", t0.Add(time.Minute), 10); len(h) != 2 {
		t.Errorf("since filter: %d entries", len(h))
	}
	if h, _ := s.History(ctx, "a.com", time.Time{}, 1); len(h) != 1 {
		t.Errorf("limit: %d entries", len(h))
	}
	if _, err := s.History(ctx, "nope.com", time.Time{}, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing watch: %v", err)
	}

	if err := s.Reschedule(ctx, id, t0.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWatch(ctx, "a.com", "seb"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCheck(ctx, id, []check.Observation{obs(t, t0, "3")}, next); !errors.Is(err, ErrNotFound) {
		t.Errorf("record on deleted watch: %v", err)
	}
	if err := s.Reschedule(ctx, id, next); !errors.Is(err, ErrNotFound) {
		t.Errorf("reschedule deleted watch: %v", err)
	}
}
