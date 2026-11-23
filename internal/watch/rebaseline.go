package watch

import (
	"maps"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

// Confirm records that actor checked the baseline of an owned watch.
func Confirm(w Watch, actor string, now time.Time) (Watch, error) {
	switch {
	case w.State == StateArchived:
		return Watch{}, ErrArchived
	case w.Template != TemplateOwned:
		return Watch{}, ErrNotOwned
	case w.BaselineCompletedAt == nil:
		return Watch{}, ErrNoBaseline
	}
	now = now.UTC().Truncate(time.Second)
	w = clone(w)
	w.BaselineConfirmedAt = &now
	w.BaselineConfirmedBy = actor
	w.UpdatedAt = now
	return w, nil
}

// Rebaseline accepts the latest facts as the new baseline: pending changes
// are dropped, volatile fields are kept, a confirmation is cleared and a
// baseline_complete event (marked rebaseline) carries the new inventory.
// Fields missing from facts (unknown) keep their old baseline value.
//
// With relearn, the watch instead starts baselining from scratch (state
// new, checked right away), which also relearns the volatile fields.
func Rebaseline(w Watch, st diff.State, facts diff.Facts, relearn bool, now time.Time) (Outcome, error) {
	if w.State == StateArchived {
		return Outcome{}, ErrArchived
	}
	now = now.UTC().Truncate(time.Second)
	w = clone(w)
	w.BaselineConfirmedAt, w.BaselineConfirmedBy = nil, ""
	w.UpdatedAt = now

	if relearn {
		w.BaselineStartedAt, w.BaselineCompletedAt = nil, nil
		w.VolatileFields = []string{}
		if w.State != StatePaused {
			w.State = StateNew
		}
		w.NextCheckAt = now
		return Outcome{Watch: w, Diff: diff.State{}}, nil
	}
	if w.BaselineCompletedAt == nil {
		return Outcome{}, ErrNoBaseline
	}
	baseline := maps.Clone(st.Baseline)
	if baseline == nil {
		baseline = map[string][]string{}
	}
	for path, vals := range facts.Values {
		baseline[path] = diff.Set(vals)
	}
	w.BaselineCompletedAt = &now
	p := payload(w)
	p.Inventory = baseline
	p.VolatileFields = w.VolatileFields
	p.Rebaseline = true
	return Outcome{
		Watch:  w,
		Diff:   diff.State{Baseline: baseline, Flags: st.Flags},
		Events: []events.Event{{Type: events.BaselineComplete, Severity: events.Info, OccurredAt: now, Payload: p}},
	}, nil
}
