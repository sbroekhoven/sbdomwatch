package watch

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

// LifecycleConfig tunes baselining and debounce.
type LifecycleConfig struct {
	BaselineObservations int           // observations needed to complete a baseline
	Debounce             int           // consecutive observations before a change is reported
	ExpiryWarning        time.Duration // owned: warn this long before the registration expires; 0 disables
	CandidateTTL         time.Duration // a change event extends an expiring candidate by this much
}

// Outcome is the result of feeding one round of facts to a watch.
type Outcome struct {
	Watch      Watch
	Diff       diff.State
	Baseline   bool           // the observations belong to the baseline
	Baselining bool           // still baselining: check again after the baseline gap
	Events     []events.Event // WatchID and ID are filled in by the store
}

// Observe advances the lifecycle of w with one round of facts:
//
//   - new: start baselining, reset all diff state.
//   - baselining: collect samples; after BaselineObservations samples (or
//     one, when the domain does not exist) learn the baseline and volatile
//     fields, emit baseline_complete and become active.
//   - active: compare with the baseline and emit an event per accepted change.
//   - paused, archived: nothing changes.
func Observe(w Watch, st diff.State, facts diff.Facts, cfg LifecycleConfig, now time.Time) Outcome {
	now = now.UTC().Truncate(time.Second)
	w = clone(w)
	out := Outcome{Diff: st}

	switch w.State {
	case StateNew, StateBaselining:
		if w.State == StateNew {
			out.Diff = diff.State{}
			w.State = StateBaselining
			w.BaselineStartedAt = &now
			w.BaselineCompletedAt = nil
			w.VolatileFields = []string{}
			w.UpdatedAt = now
		}
		out.Baseline = true
		out.Diff.Samples = append(out.Diff.Samples, maps.Clone(facts.Values))
		if len(out.Diff.Samples) < max(cfg.BaselineObservations, 1) && !facts.Absent {
			out.Baselining = true
			break
		}
		baseline, volatile := diff.Learn(out.Diff.Samples)
		n := len(out.Diff.Samples)
		out.Diff = diff.State{Baseline: baseline}
		w.State = StateActive
		w.BaselineCompletedAt = &now
		w.VolatileFields = volatile
		w.UpdatedAt = now
		p := payload(w)
		p.Inventory = baseline
		p.VolatileFields = volatile
		p.Observations = n
		out.Events = append(out.Events, events.Event{Type: events.BaselineComplete, Severity: events.Info, OccurredAt: now, Payload: p})

	case StateActive:
		var changes []diff.Change
		out.Diff, changes = diff.Compare(st, facts.Values, diff.CompareOptions{
			Volatile:  w.VolatileFields,
			Debounce:  cfg.Debounce,
			Immediate: registering(st, facts),
		})
		owned := w.Template == TemplateOwned
		changes, foldedReg := foldRegistration(changes)
		changes, foldedDangling := foldDangling(changes)
		for _, c := range changes {
			typ, sev := events.ForChange(c, owned)
			p := payload(w)
			p.Change = &c
			switch c.Path {
			case events.PathRegistered:
				p.Details = foldedReg
			case events.PathDangling:
				p.Details = foldedDangling
			}
			out.Events = append(out.Events, events.Event{Type: typ, Severity: sev, OccurredAt: now, Payload: p})
		}
		if len(out.Events) > 0 && w.ExpiresAt != nil && cfg.CandidateTTL > 0 {
			exp := now.Add(cfg.CandidateTTL) // a notable change keeps a candidate alive
			w.ExpiresAt = &exp
			w.UpdatedAt = now
		}
	}
	if w.State == StateActive {
		if e, ok := expiring(w, &out.Diff, facts, cfg, now); ok {
			out.Events = append(out.Events, e)
		}
	}
	out.Watch = w
	return out
}

// registering returns the Immediate rule for diff.Compare: when RDAP now
// shows an unregistered domain as registered, every RDAP field is accepted
// at once, so registered fires immediately (as the plan wants) and carries
// the new registrar and nameservers.
func registering(st diff.State, f diff.Facts) func(path string, before, after []string) bool {
	on := slices.Equal(st.Baseline[events.PathRegistered], []string{"false"}) &&
		slices.Equal(f.Values[events.PathRegistered], []string{"true"})
	return func(path string, _, _ []string) bool {
		return on && strings.HasPrefix(path, "rdap.")
	}
}

// foldRegistration moves other RDAP changes of the same round into the
// details of a registered or dropped event: a new registrar and
// nameservers are part of the registration, not separate news.
func foldRegistration(changes []diff.Change) (kept, folded []diff.Change) {
	reg := slices.ContainsFunc(changes, func(c diff.Change) bool { return c.Path == events.PathRegistered })
	if !reg {
		return changes, nil
	}
	for _, c := range changes {
		if c.Path != events.PathRegistered && strings.HasPrefix(c.Path, "rdap.") {
			folded = append(folded, c)
			continue
		}
		kept = append(kept, c)
	}
	return kept, folded
}

// foldDangling moves A and AAAA removals into a dangling_cname event: they
// are the symptom, the dead CNAME target is the news.
func foldDangling(changes []diff.Change) (kept, folded []diff.Change) {
	dangling := slices.ContainsFunc(changes, func(c diff.Change) bool {
		return c.Path == events.PathDangling && c.Kind != diff.Removed
	})
	if !dangling {
		return changes, nil
	}
	for _, c := range changes {
		if (c.Path == events.PathDNSA || c.Path == events.PathDNSAAAA) && c.Kind == diff.Removed {
			folded = append(folded, c)
			continue
		}
		kept = append(kept, c)
	}
	return kept, folded
}

const flagExpiring = "expiring"

// expiring warns once per expiry date when an owned domain's registration
// expires within the warning window. A renewal moves the date and re-arms it.
func expiring(w Watch, st *diff.State, f diff.Facts, cfg LifecycleConfig, now time.Time) (events.Event, bool) {
	raw, ok := f.Meta["rdap.expiry"]
	if w.Template != TemplateOwned || cfg.ExpiryWarning <= 0 || !ok {
		return events.Event{}, false
	}
	exp, err := time.Parse(time.RFC3339, raw)
	if err != nil || exp.Sub(now) > cfg.ExpiryWarning || st.Flags[flagExpiring] == raw {
		return events.Event{}, false
	}
	if st.Flags == nil {
		st.Flags = map[string]string{}
	}
	st.Flags[flagExpiring] = raw
	p := payload(w)
	p.Expiry = &exp
	return events.Event{Type: events.Expiring, Severity: events.Medium, OccurredAt: now, Payload: p}, true
}

func payload(w Watch) events.Payload {
	p := events.Payload{Domain: w.Domain, Template: string(w.Template), Origins: []events.OriginRef{},
		BaselineConfirmed: w.BaselineConfirmedAt != nil}
	for _, o := range w.Origins {
		p.Origins = append(p.Origins, events.OriginRef{Origin: string(o.Origin), Reason: o.Reason, Reference: o.Reference})
	}
	if len(w.Tags) > 0 {
		p.Tags = maps.Clone(w.Tags)
	}
	return p
}
