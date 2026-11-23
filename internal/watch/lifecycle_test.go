package watch

import (
	"slices"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

var lc = LifecycleConfig{BaselineObservations: 3, Debounce: 2}

func facts(kv ...any) diff.Facts {
	f := diff.Facts{Values: map[string][]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Values[kv[i].(string)] = kv[i+1].([]string)
	}
	return f
}

func newWatch() Watch {
	return Watch{
		Domain: "example.com", Template: TemplateOwned, State: StateNew,
		Tags:    map[string]string{"profile": "x"},
		Origins: []Origin{{Origin: OriginManual, Reason: "company domain", Reference: "R-1"}},
	}
}

func TestBaselining(t *testing.T) {
	w := newWatch()
	var st diff.State
	clock := t0

	rounds := []diff.Facts{
		facts("dns.A", []string{"1", "2"}, "dns.MX", []string{}),
		facts("dns.A", []string{"3", "4"}, "dns.MX", []string{}),
		facts("dns.A", []string{"1", "2"}, "dns.MX", []string{}, "dns.NS", []string{"ns1"}),
	}
	for i, f := range rounds {
		out := Observe(w, st, f, lc, clock)
		w, st = out.Watch, out.Diff
		last := i == len(rounds)-1
		if !out.Baseline || out.Baselining == last {
			t.Fatalf("round %d: baseline=%v baselining=%v", i, out.Baseline, out.Baselining)
		}
		if i == 0 && (w.State != StateBaselining || !w.BaselineStartedAt.Equal(t0)) {
			t.Fatalf("first round: %+v", w)
		}
		if !last && len(out.Events) != 0 {
			t.Fatalf("round %d: events during baselining: %+v", i, out.Events)
		}
		if last {
			if w.State != StateActive || !w.BaselineCompletedAt.Equal(clock) || !slices.Equal(w.VolatileFields, []string{"dns.A"}) {
				t.Fatalf("after baseline: %+v", w)
			}
			if len(out.Events) != 1 || out.Events[0].Type != events.BaselineComplete || out.Events[0].Severity != events.Info {
				t.Fatalf("events = %+v", out.Events)
			}
			p := out.Events[0].Payload
			if p.Domain != "example.com" || p.Template != "owned" || len(p.Origins) != 1 || p.Origins[0].Reference != "R-1" ||
				p.Observations != 3 || !slices.Equal(p.Inventory["dns.NS"], []string{"ns1"}) || p.Tags["profile"] != "x" {
				t.Errorf("payload = %+v", p)
			}
			if len(st.Samples) != 0 || len(st.Baseline) != 3 {
				t.Errorf("diff state = %+v", st)
			}
		}
		clock = clock.Add(3 * time.Minute)
	}
}

func TestAbsentDomainBaselinesOnce(t *testing.T) {
	f := facts("dns.A", []string{}, "dns.NS", []string{})
	f.Absent = true
	out := Observe(newWatch(), diff.State{}, f, lc, t0)
	if out.Watch.State != StateActive || out.Baselining || len(out.Events) != 1 {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestActiveEmitsEvents(t *testing.T) {
	w := newWatch()
	w.State = StateActive
	st := diff.State{Baseline: map[string][]string{"dns.MX": {}, "dns.NS": {"ns1"}}}
	steps := []struct {
		f    diff.Facts
		want []events.Type
	}{
		{facts("dns.MX", []string{"10 mx"}, "dns.NS", []string{"ns2"}), nil},
		{facts("dns.MX", []string{"10 mx"}, "dns.NS", []string{"ns2"}), []events.Type{events.MXAppeared, events.NSChanged}},
		{facts("dns.MX", []string{"10 mx"}, "dns.NS", []string{"ns2"}), nil},
	}
	for i, s := range steps {
		out := Observe(w, st, s.f, lc, t0)
		w, st = out.Watch, out.Diff
		var got []events.Type
		for _, e := range out.Events {
			got = append(got, e.Type)
			if e.Payload.Change == nil {
				t.Errorf("step %d: change missing in payload", i)
			}
		}
		if !slices.Equal(got, s.want) || out.Baseline {
			t.Fatalf("step %d: events %v, want %v", i, got, s.want)
		}
	}
	if w.State != StateActive {
		t.Errorf("state = %s", w.State)
	}
}

func TestOwnedNSIsCritical(t *testing.T) {
	for _, tmpl := range []Template{TemplateOwned, TemplateCandidate} {
		w := newWatch()
		w.State, w.Template = StateActive, tmpl
		st := diff.State{Baseline: map[string][]string{"dns.NS": {"ns1"}}}
		lc1 := LifecycleConfig{BaselineObservations: 3, Debounce: 1}
		out := Observe(w, st, facts("dns.NS", []string{"evil"}), lc1, t0)
		want := events.High
		if tmpl == TemplateOwned {
			want = events.Critical
		}
		if len(out.Events) != 1 || out.Events[0].Severity != want {
			t.Errorf("%s: %+v", tmpl, out.Events)
		}
	}
}

func TestNewResetsState(t *testing.T) {
	w := newWatch() // state new, e.g. after resume without baseline or re-add of an archived watch
	stale := diff.State{Baseline: map[string][]string{"dns.A": {"old"}}, Samples: []map[string][]string{{"x": {"y"}}}}
	out := Observe(w, stale, facts("dns.A", []string{"1"}), lc, t0)
	if len(out.Diff.Samples) != 1 || out.Diff.Baseline != nil {
		t.Errorf("stale state kept: %+v", out.Diff)
	}
}

func TestPausedIsUntouched(t *testing.T) {
	for _, s := range []State{StatePaused, StateArchived} {
		w := newWatch()
		w.State = s
		st := diff.State{Baseline: map[string][]string{"dns.A": {"1"}}}
		out := Observe(w, st, facts("dns.A", []string{"2"}), LifecycleConfig{Debounce: 1}, t0)
		if out.Watch.State != s || len(out.Events) != 0 || out.Baseline || out.Diff.Baseline["dns.A"][0] != "1" {
			t.Errorf("%s: %+v", s, out)
		}
	}
}
