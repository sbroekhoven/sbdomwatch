package watch

import (
	"maps"
	"reflect"
	"slices"
	"time"
)

// Defaults are the settings used for new watches.
type Defaults struct {
	Intervals    map[Template]time.Duration
	CandidateTTL time.Duration // candidates are archived after this long without a notable change
}

func (d Defaults) intervalSec(t Template) int {
	return int(d.Intervals[t] / time.Second)
}

// Apply adds req to existing, or creates a new watch when existing is nil.
// req must be normalized. It reports whether a watch was created and whether
// anything changed.
//
// Merge rules: origins are added unless the same origin and reason exist,
// tags are merged with new values winning, the template only moves up
// (candidate, third-party, owned), and an archived watch starts over as new.
func Apply(existing *Watch, req AddRequest, actor string, now time.Time, d Defaults) (w Watch, created, changed bool) {
	now = now.UTC().Truncate(time.Second)
	origin := Origin{Origin: req.Origin, Reason: req.Reason, Reference: req.Reference, AddedBy: actor, AddedAt: now}

	if existing == nil {
		w = Watch{
			Domain:         req.Domain,
			Template:       req.Template,
			State:          StateNew,
			IntervalSec:    req.IntervalSec,
			NextCheckAt:    now,
			VolatileFields: []string{},
			Tags:           map[string]string{},
			CreatedAt:      now,
			UpdatedAt:      now,
			Origins:        []Origin{origin},
		}
		if w.IntervalSec == 0 {
			w.IntervalSec = d.intervalSec(req.Template)
		}
		maps.Copy(w.Tags, req.Tags)
		if w.Template == TemplateCandidate {
			exp := now.Add(d.CandidateTTL)
			w.ExpiresAt = &exp
		}
		return w, true, true
	}

	orig := clone(*existing)
	w = clone(orig)
	if req.Template.rank() > w.Template.rank() {
		w.Template = req.Template
		if req.IntervalSec == 0 {
			w.IntervalSec = min(w.IntervalSec, d.intervalSec(req.Template))
		}
	}
	if req.IntervalSec != 0 {
		w.IntervalSec = req.IntervalSec
	}
	maps.Copy(w.Tags, req.Tags)

	hasOrigin := slices.ContainsFunc(w.Origins, func(o Origin) bool {
		return o.Origin == origin.Origin && o.Reason == origin.Reason
	})
	if !hasOrigin {
		w.Origins = append(w.Origins, origin)
	}

	switch {
	case w.Template != TemplateCandidate:
		w.ExpiresAt = nil
	case !hasOrigin:
		exp := now.Add(d.CandidateTTL)
		w.ExpiresAt = &exp
	}

	if w.State == StateArchived {
		w.State = StateNew
		w.NextCheckAt = now
		w.BaselineStartedAt = nil
		w.BaselineCompletedAt = nil
		w.VolatileFields = []string{}
	}

	changed = !reflect.DeepEqual(w, orig)
	if changed {
		w.UpdatedAt = now
	}
	return w, false, changed
}

// ApplyPatch applies a validated patch. It returns ErrArchived for an
// archived watch.
func ApplyPatch(existing Watch, p PatchRequest, now time.Time) (w Watch, changed bool, err error) {
	if existing.State == StateArchived {
		return Watch{}, false, ErrArchived
	}
	now = now.UTC().Truncate(time.Second)
	orig := clone(existing)
	w = clone(orig)
	if p.Paused != nil {
		switch {
		case *p.Paused && w.State != StatePaused:
			w.State = StatePaused
		case !*p.Paused && w.State == StatePaused:
			w.State = StateNew
			if w.BaselineCompletedAt != nil {
				w.State = StateActive
			}
			w.NextCheckAt = now
		}
	}
	if p.IntervalSec != nil {
		w.IntervalSec = *p.IntervalSec
	}
	for k, v := range p.Tags {
		if v == nil {
			delete(w.Tags, k)
		} else {
			w.Tags[k] = *v
		}
	}
	changed = !reflect.DeepEqual(w, orig)
	if changed {
		w.UpdatedAt = now
	}
	return w, changed, nil
}

// Archive stops checks on a watch. It reports whether anything changed.
func Archive(existing Watch, now time.Time) (Watch, bool) {
	if existing.State == StateArchived {
		return existing, false
	}
	w := clone(existing)
	w.State = StateArchived
	w.UpdatedAt = now.UTC().Truncate(time.Second)
	return w, true
}

func clone(w Watch) Watch {
	w.Tags = maps.Clone(w.Tags)
	if w.Tags == nil {
		w.Tags = map[string]string{}
	}
	w.Origins = slices.Clone(w.Origins)
	w.VolatileFields = slices.Clone(w.VolatileFields)
	if w.VolatileFields == nil {
		w.VolatileFields = []string{}
	}
	return w
}
