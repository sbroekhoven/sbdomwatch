// Package diff compares observations as sets of facts: it learns a baseline
// and volatile fields from the first observations and then reports changes
// that persist for several consecutive observations (debounce).
//
// A fact is a field path such as "dns.MX" with a set of values. Order and
// duplicates do not matter. A path missing from an observation is unknown
// (for example the resolver failed) and is never treated as a change.
package diff

import (
	"encoding/json"
	"maps"
	"slices"
)

// Facts are the comparable contents of one round of observations.
type Facts struct {
	// Values maps a field path to its set of values. An empty set means
	// "known to be empty"; a missing path means unknown.
	Values map[string][]string
	// Absent is true when the domain does not exist according to the data.
	Absent bool
}

// Extractor turns one check's observation data into facts.
type Extractor func(data json.RawMessage) (Facts, error)

// Merge combines facts from several checks. Paths must not overlap; each
// check prefixes its own.
func Merge(fs ...Facts) Facts {
	out := Facts{Values: map[string][]string{}}
	for _, f := range fs {
		maps.Copy(out.Values, f.Values)
		out.Absent = out.Absent || f.Absent
	}
	return out
}

// Set returns values sorted and without duplicates, never nil.
func Set(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// Pending is a candidate change that has not been seen often enough yet.
type Pending struct {
	Values []string `json:"values"`
	Count  int      `json:"count"`
}

// State is persisted per watch between observations.
type State struct {
	// Baseline holds the accepted values per path.
	Baseline map[string][]string `json:"baseline,omitempty"`
	// Pending holds candidate changes per path.
	Pending map[string]Pending `json:"pending,omitempty"`
	// Samples collects facts while baselining, oldest first.
	Samples []map[string][]string `json:"samples,omitempty"`
}

// ChangeKind says how a path changed.
type ChangeKind string

// Change kinds.
const (
	Added   ChangeKind = "added"   // was empty, now has values
	Removed ChangeKind = "removed" // had values, now empty
	Changed ChangeKind = "changed" // values differ, neither side empty
)

// Change is an accepted difference for one path.
type Change struct {
	Path    string     `json:"path"`
	Kind    ChangeKind `json:"kind"`
	Before  []string   `json:"before"`
	After   []string   `json:"after"`
	Added   []string   `json:"added"`
	Removed []string   `json:"removed"`
}

// Learn derives the baseline and the volatile paths from baseline samples.
// A path is volatile when its known values differ between samples. The
// baseline holds the latest known value of every path, volatile or not.
func Learn(samples []map[string][]string) (baseline map[string][]string, volatile []string) {
	baseline = map[string][]string{}
	seen := map[string][]string{}
	for _, s := range samples {
		for path, vals := range s {
			v := Set(vals)
			if prev, ok := seen[path]; ok && !slices.Equal(prev, v) && !slices.Contains(volatile, path) {
				volatile = append(volatile, path)
			}
			seen[path] = v
			baseline[path] = v
		}
	}
	slices.Sort(volatile)
	if volatile == nil {
		volatile = []string{}
	}
	return baseline, volatile
}

// Compare checks facts against the baseline. A difference becomes a Change
// once the same new values were seen in debounce consecutive observations;
// the baseline then moves to the new values so the change is reported once.
// Volatile paths are ignored. A path seen for the first time is adopted
// into the baseline without a change.
func Compare(st State, facts map[string][]string, volatile []string, debounce int) (State, []Change) {
	debounce = max(debounce, 1)
	out := State{Baseline: maps.Clone(st.Baseline), Pending: maps.Clone(st.Pending)}
	if out.Baseline == nil {
		out.Baseline = map[string][]string{}
	}
	if out.Pending == nil {
		out.Pending = map[string]Pending{}
	}
	var changes []Change
	for _, path := range slices.Sorted(maps.Keys(facts)) {
		if slices.Contains(volatile, path) {
			delete(out.Pending, path)
			continue
		}
		now := Set(facts[path])
		base, ok := out.Baseline[path]
		if !ok {
			out.Baseline[path] = now
			continue
		}
		if slices.Equal(base, now) {
			delete(out.Pending, path)
			continue
		}
		p := out.Pending[path]
		if slices.Equal(p.Values, now) {
			p.Count++
		} else {
			p = Pending{Values: now, Count: 1}
		}
		if p.Count < debounce {
			out.Pending[path] = p
			continue
		}
		delete(out.Pending, path)
		out.Baseline[path] = now
		changes = append(changes, newChange(path, base, now))
	}
	if len(out.Pending) == 0 {
		out.Pending = nil
	}
	return out, changes
}

func newChange(path string, before, after []string) Change {
	c := Change{Path: path, Before: before, After: after, Added: []string{}, Removed: []string{}}
	for _, v := range after {
		if !slices.Contains(before, v) {
			c.Added = append(c.Added, v)
		}
	}
	for _, v := range before {
		if !slices.Contains(after, v) {
			c.Removed = append(c.Removed, v)
		}
	}
	switch {
	case len(before) == 0:
		c.Kind = Added
	case len(after) == 0:
		c.Kind = Removed
	default:
		c.Kind = Changed
	}
	return c
}
