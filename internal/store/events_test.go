package store

import (
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// emit stores events for domain through ApplyCheck with the given routes.
func emit(t *testing.T, s *Store, domain string, evs []events.Event, routes [][]string) []events.Event {
	t.Helper()
	w, err := s.GetWatch(t.Context(), domain)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.ApplyCheck(t.Context(), w.ID, func(w watch.Watch, st diff.State) (CheckResult, error) {
		return CheckResult{Watch: w, Diff: st, Events: evs, Routes: routes, Next: w.NextCheckAt}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestOutbox(t *testing.T) {
	s, clock := newStore(t)
	ctx := t.Context()
	add(t, s, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x"})
	now := clock.Now()
	ev := func(typ events.Type, sev events.Severity) events.Event {
		return events.Event{Type: typ, Severity: sev, OccurredAt: now, Payload: events.Payload{Domain: "a.com"}}
	}
	stored := emit(t, s, "a.com",
		[]events.Event{ev(events.BaselineComplete, events.Info), ev(events.MXAppeared, events.High)},
		[][]string{{"webhook"}, {"discord", "webhook"}})
	if len(stored) != 2 || stored[0].ID == 0 {
		t.Fatalf("stored = %+v", stored)
	}

	due, err := s.DueDeliveries(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 3 || due[0].Event.Type != events.BaselineComplete || due[0].Sink != "webhook" ||
		due[1].Sink != "discord" || due[1].Event.Payload.Domain != "a.com" {
		t.Fatalf("due = %+v", due)
	}

	mx := stored[1].ID
	if err := s.MarkFailed(ctx, mx, "discord", "HTTP 503", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered(ctx, mx, "webhook", now); err != nil {
		t.Fatal(err)
	}
	due, _ = s.DueDeliveries(ctx, now, 10)
	if len(due) != 1 || due[0].Sink != "webhook" || due[0].Event.ID != stored[0].ID {
		t.Fatalf("after mark: due = %+v", due)
	}
	due, _ = s.DueDeliveries(ctx, now.Add(time.Minute), 10)
	if len(due) != 2 || due[1].Sink != "discord" || due[1].Attempts != 1 {
		t.Fatalf("retry due = %+v", due)
	}
	stats, _ := s.OutboxStats(ctx)
	if stats["discord"] != 1 || stats["webhook"] != 1 {
		t.Errorf("stats = %v", stats)
	}
	var lastErr string
	if err := s.r.QueryRow(`SELECT last_error FROM event_deliveries WHERE event_id = ? AND sink = 'discord'`, mx).Scan(&lastErr); err != nil || lastErr != "HTTP 503" {
		t.Errorf("last_error = %q, %v", lastErr, err)
	}
}

func TestListEvents(t *testing.T) {
	s, clock := newStore(t)
	ctx := t.Context()
	add(t, s, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned, Reason: "x"})
	add(t, s, watch.AddRequest{Domain: "b.com", Template: watch.TemplateOwned, Reason: "x"})
	t0 := clock.Now()
	at := func(d time.Duration, typ events.Type, sev events.Severity) events.Event {
		return events.Event{Type: typ, Severity: sev, OccurredAt: t0.Add(d)}
	}
	emit(t, s, "a.com", []events.Event{at(0, events.BaselineComplete, events.Info), at(2*time.Hour, events.MXAppeared, events.High)}, nil)
	emit(t, s, "b.com", []events.Event{at(time.Hour, events.NSChanged, events.Critical), at(3*time.Hour, events.RecordAdded, events.Medium)}, nil)

	tests := []struct {
		name string
		f    EventFilter
		want []events.Type
	}{
		{"all newest first", EventFilter{Limit: 10}, []events.Type{events.RecordAdded, events.MXAppeared, events.NSChanged, events.BaselineComplete}},
		{"limit", EventFilter{Limit: 1}, []events.Type{events.RecordAdded}},
		{"since", EventFilter{Since: t0.Add(90 * time.Minute), Limit: 10}, []events.Type{events.RecordAdded, events.MXAppeared}},
		{"domain", EventFilter{Domain: "a.com", Limit: 10}, []events.Type{events.MXAppeared, events.BaselineComplete}},
		{"unknown domain", EventFilter{Domain: "nope.com", Limit: 10}, nil},
		{"types", EventFilter{Types: []events.Type{events.NSChanged, events.MXAppeared}, Limit: 10}, []events.Type{events.MXAppeared, events.NSChanged}},
		{"min severity high", EventFilter{MinSeverity: events.High, Limit: 10}, []events.Type{events.MXAppeared, events.NSChanged}},
		{"min severity info", EventFilter{MinSeverity: events.Info, Limit: 10}, []events.Type{events.RecordAdded, events.MXAppeared, events.NSChanged, events.BaselineComplete}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ListEvents(ctx, tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d events, want %v", len(got), tt.want)
			}
			for i := range got {
				if got[i].Type != tt.want[i] {
					t.Fatalf("event %d = %s, want %v", i, got[i].Type, tt.want)
				}
			}
		})
	}
}
