package watch

import (
	"errors"
	"slices"
	"testing"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

func TestConfirm(t *testing.T) {
	done := t0
	active := newWatch()
	active.State, active.BaselineCompletedAt = StateActive, &done

	tests := []struct {
		name    string
		mutate  func(w *Watch)
		wantErr error
	}{
		{"owned with baseline", func(w *Watch) {}, nil},
		{"paused owned is fine", func(w *Watch) { w.State = StatePaused }, nil},
		{"candidate", func(w *Watch) { w.Template = TemplateCandidate }, ErrNotOwned},
		{"still baselining", func(w *Watch) { w.State, w.BaselineCompletedAt = StateBaselining, nil }, ErrNoBaseline},
		{"archived", func(w *Watch) { w.State = StateArchived }, ErrArchived},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := clone(active)
			tt.mutate(&w)
			got, err := Confirm(w, "seb", t1)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && (got.BaselineConfirmedAt == nil || !got.BaselineConfirmedAt.Equal(t1) || got.BaselineConfirmedBy != "seb") {
				t.Errorf("got %+v", got)
			}
		})
	}
}

func TestRebaseline(t *testing.T) {
	done, conf := t0, t0
	w := newWatch()
	w.State, w.BaselineCompletedAt, w.BaselineConfirmedAt, w.BaselineConfirmedBy = StateActive, &done, &conf, "seb"
	w.VolatileFields = []string{"dns.A"}
	st := diff.State{
		Baseline: map[string][]string{"dns.NS": {"old"}, "dns.MX": {}, "dns.TXT": {"keep"}},
		Pending:  map[string]diff.Pending{"dns.NS": {Values: []string{"new"}, Count: 1}},
		Flags:    map[string]string{"expiring": "2027-01-01T00:00:00Z"},
	}
	f := facts("dns.NS", []string{"new"}, "dns.MX", []string{"10 mx"}) // TXT unknown

	out, err := Rebaseline(w, st, f, false, t1)
	if err != nil {
		t.Fatal(err)
	}
	b := out.Diff.Baseline
	if !slices.Equal(b["dns.NS"], []string{"new"}) || !slices.Equal(b["dns.MX"], []string{"10 mx"}) || !slices.Equal(b["dns.TXT"], []string{"keep"}) {
		t.Errorf("baseline = %v", b)
	}
	if len(out.Diff.Pending) != 0 || out.Diff.Flags["expiring"] == "" {
		t.Errorf("diff state = %+v (pending must go, flags stay)", out.Diff)
	}
	if out.Watch.BaselineConfirmedAt != nil || !out.Watch.BaselineCompletedAt.Equal(t1) || !slices.Equal(out.Watch.VolatileFields, []string{"dns.A"}) {
		t.Errorf("watch = %+v", out.Watch)
	}
	if len(out.Events) != 1 || out.Events[0].Type != events.BaselineComplete || !out.Events[0].Payload.Rebaseline {
		t.Errorf("events = %+v", out.Events)
	}
	if st.Baseline["dns.NS"][0] != "old" {
		t.Error("Rebaseline modified its input")
	}

	// Relearn starts over.
	out, err = Rebaseline(w, st, f, true, t1)
	if err != nil {
		t.Fatal(err)
	}
	if out.Watch.State != StateNew || out.Watch.BaselineCompletedAt != nil || len(out.Watch.VolatileFields) != 0 ||
		!out.Watch.NextCheckAt.Equal(t1) || out.Diff.Baseline != nil || len(out.Events) != 0 {
		t.Errorf("relearn = %+v", out)
	}
	paused := clone(w)
	paused.State = StatePaused
	if out, _ := Rebaseline(paused, st, f, true, t1); out.Watch.State != StatePaused {
		t.Errorf("relearn unpaused the watch: %s", out.Watch.State)
	}

	baselining := newWatch()
	baselining.State = StateBaselining
	if _, err := Rebaseline(baselining, st, f, false, t1); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("rebaseline while baselining: %v", err)
	}
	archived := clone(w)
	archived.State = StateArchived
	if _, err := Rebaseline(archived, st, f, true, t1); !errors.Is(err, ErrArchived) {
		t.Errorf("rebaseline archived: %v", err)
	}
}
