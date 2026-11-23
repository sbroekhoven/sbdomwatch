package watch

import (
	"errors"
	"testing"
	"time"
)

var (
	t0       = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	t1       = t0.Add(time.Hour)
	defaults = Defaults{
		Intervals: map[Template]time.Duration{
			TemplateOwned:      time.Hour,
			TemplateCandidate:  6 * time.Hour,
			TemplateThirdParty: 6 * time.Hour,
		},
		CandidateTTL: 90 * 24 * time.Hour,
	}
)

func req(t *testing.T, r AddRequest) AddRequest {
	t.Helper()
	n, err := r.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplyNew(t *testing.T) {
	r := req(t, AddRequest{Domain: "degir0.com", Template: TemplateCandidate, Reason: "seen in CT", Tags: map[string]string{"profile": "degiro"}})
	w, created, changed := Apply(nil, r, "seb", t0, defaults)
	if !created || !changed {
		t.Fatalf("created=%v changed=%v", created, changed)
	}
	if w.State != StateNew || !w.NextCheckAt.Equal(t0) || w.IntervalSec != 6*3600 {
		t.Errorf("unexpected watch: %+v", w)
	}
	if w.ExpiresAt == nil || !w.ExpiresAt.Equal(t0.Add(defaults.CandidateTTL)) {
		t.Errorf("candidate expiry = %v", w.ExpiresAt)
	}
	if len(w.Origins) != 1 || w.Origins[0].AddedBy != "seb" || w.Origins[0].Origin != OriginManual {
		t.Errorf("origins = %+v", w.Origins)
	}
	if w.Tags["profile"] != "degiro" {
		t.Errorf("tags = %v", w.Tags)
	}
}

func TestApplyMerge(t *testing.T) {
	base, _, _ := Apply(nil, req(t, AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1", Tags: map[string]string{"a": "1", "b": "1"}}), "seb", t0, defaults)

	tests := []struct {
		name        string
		start       func() Watch
		in          AddRequest
		wantChanged bool
		check       func(t *testing.T, w Watch)
	}{
		{
			name:        "same request is a no-op",
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1", Tags: map[string]string{"a": "1"}},
			wantChanged: false,
			check: func(t *testing.T, w Watch) {
				if len(w.Origins) != 1 || !w.UpdatedAt.Equal(t0) {
					t.Errorf("no-op changed the watch: %+v", w)
				}
			},
		},
		{
			name:        "new reason adds origin and refreshes expiry",
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r2", Origin: OriginTyposquat, Reference: "T-1"},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if len(w.Origins) != 2 || w.Origins[1].Reason != "r2" || w.Origins[1].Reference != "T-1" {
					t.Errorf("origins = %+v", w.Origins)
				}
				if !w.ExpiresAt.Equal(t1.Add(defaults.CandidateTTL)) || !w.UpdatedAt.Equal(t1) {
					t.Errorf("expiry=%v updated=%v", w.ExpiresAt, w.UpdatedAt)
				}
			},
		},
		{
			name:        "same reason other origin kind is a new origin",
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1", Origin: OriginIntel},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if len(w.Origins) != 2 {
					t.Errorf("origins = %+v", w.Origins)
				}
			},
		},
		{
			name:        "tags merge, new values win",
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1", Tags: map[string]string{"b": "2", "c": "3"}},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if w.Tags["a"] != "1" || w.Tags["b"] != "2" || w.Tags["c"] != "3" {
					t.Errorf("tags = %v", w.Tags)
				}
			},
		},
		{
			name:        "template upgrade to owned clears expiry and shortens interval",
			in:          AddRequest{Domain: "example.com", Template: TemplateOwned, Reason: "ours now"},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if w.Template != TemplateOwned || w.ExpiresAt != nil || w.IntervalSec != 3600 {
					t.Errorf("got %+v", w)
				}
			},
		},
		{
			name: "template never downgrades",
			start: func() Watch {
				w := clone(base)
				w.Template = TemplateOwned
				w.ExpiresAt = nil
				return w
			},
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1"},
			wantChanged: false,
			check: func(t *testing.T, w Watch) {
				if w.Template != TemplateOwned || w.ExpiresAt != nil {
					t.Errorf("got %+v", w)
				}
			},
		},
		{
			name:        "explicit interval wins",
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "r1", IntervalSec: 600},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if w.IntervalSec != 600 {
					t.Errorf("interval = %d", w.IntervalSec)
				}
			},
		},
		{
			name: "archived watch starts over",
			start: func() Watch {
				w := clone(base)
				w.State = StateArchived
				done := t0
				w.BaselineCompletedAt = &done
				w.VolatileFields = []string{"dns.a"}
				return w
			},
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "back"},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if w.State != StateNew || w.BaselineCompletedAt != nil || len(w.VolatileFields) != 0 || !w.NextCheckAt.Equal(t1) {
					t.Errorf("got %+v", w)
				}
			},
		},
		{
			name: "paused watch stays paused",
			start: func() Watch {
				w := clone(base)
				w.State = StatePaused
				return w
			},
			in:          AddRequest{Domain: "example.com", Template: TemplateCandidate, Reason: "again"},
			wantChanged: true,
			check: func(t *testing.T, w Watch) {
				if w.State != StatePaused {
					t.Errorf("state = %s", w.State)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := clone(base)
			if tt.start != nil {
				start = tt.start()
			}
			before := clone(start)
			w, created, changed := Apply(&start, req(t, tt.in), "seb", t1, defaults)
			if created {
				t.Error("created = true for an existing watch")
			}
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
			tt.check(t, w)
			if len(start.Origins) != len(before.Origins) || len(start.Tags) != len(before.Tags) {
				t.Error("Apply modified its input")
			}
		})
	}
}

func TestApplyPatch(t *testing.T) {
	yes, no := true, false
	iv := 900
	val := "x"
	done := t0
	active := Watch{State: StateActive, BaselineCompletedAt: &done, IntervalSec: 3600, Tags: map[string]string{"a": "1"}, NextCheckAt: t0, UpdatedAt: t0}
	fresh := Watch{State: StateNew, IntervalSec: 3600, Tags: map[string]string{}, NextCheckAt: t0, UpdatedAt: t0}

	pausedFrom := func(w Watch) Watch { w = clone(w); w.State = StatePaused; return w }

	tests := []struct {
		name        string
		in          Watch
		p           PatchRequest
		wantState   State
		wantChanged bool
		wantErr     error
	}{
		{name: "pause", in: active, p: PatchRequest{Paused: &yes}, wantState: StatePaused, wantChanged: true},
		{name: "pause twice", in: pausedFrom(active), p: PatchRequest{Paused: &yes}, wantState: StatePaused},
		{name: "resume with baseline", in: pausedFrom(active), p: PatchRequest{Paused: &no}, wantState: StateActive, wantChanged: true},
		{name: "resume without baseline", in: pausedFrom(fresh), p: PatchRequest{Paused: &no}, wantState: StateNew, wantChanged: true},
		{name: "resume when not paused", in: active, p: PatchRequest{Paused: &no}, wantState: StateActive},
		{name: "interval", in: active, p: PatchRequest{IntervalSec: &iv}, wantState: StateActive, wantChanged: true},
		{name: "set and remove tags", in: active, p: PatchRequest{Tags: map[string]*string{"a": nil, "b": &val}}, wantState: StateActive, wantChanged: true},
		{name: "archived", in: Watch{State: StateArchived}, p: PatchRequest{Paused: &yes}, wantErr: ErrArchived},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, changed, err := ApplyPatch(tt.in, tt.p, t1)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if w.State != tt.wantState || changed != tt.wantChanged {
				t.Errorf("state=%s changed=%v, want %s %v", w.State, changed, tt.wantState, tt.wantChanged)
			}
			if changed && !w.UpdatedAt.Equal(t1) {
				t.Errorf("updated_at not bumped")
			}
		})
	}
	w, _, _ := ApplyPatch(active, PatchRequest{Tags: map[string]*string{"a": nil, "b": &val}}, t1)
	if _, ok := w.Tags["a"]; ok || w.Tags["b"] != "x" {
		t.Errorf("tags = %v", w.Tags)
	}
	if active.Tags["a"] != "1" {
		t.Error("ApplyPatch modified its input")
	}
}

func TestArchive(t *testing.T) {
	w, changed := Archive(Watch{State: StateActive}, t1)
	if !changed || w.State != StateArchived || !w.UpdatedAt.Equal(t1) {
		t.Errorf("got %+v %v", w, changed)
	}
	if _, changed := Archive(w, t1); changed {
		t.Error("archiving twice reported a change")
	}
}
