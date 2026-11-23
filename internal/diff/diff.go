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
	// Exists is true when an authoritative source (RDAP) says the domain
	// is registered; it overrides Absent from other sources.
	Exists bool
	// Meta holds values that are passed along but never compared, such as
	// "rdap.expiry" (RFC 3339).
	Meta map[string]string
}

// Extractor turns one check's observation data into facts.
type Extractor func(data json.RawMessage) (Facts, error)

// Merge combines facts from several checks. Paths must not overlap; each
// check prefixes its own. The result is absent when some check says so and
// none says the domain exists.
func Merge(fs ...Facts) Facts {
	out := Facts{Values: map[string][]string{}, Meta: map[string]string{}}
	for _, f := range fs {
		maps.Copy(out.Values, f.Values)
		maps.Copy(out.Meta, f.Meta)
		out.Absent = out.Absent || f.Absent
		out.Exists = out.Exists || f.Exists
	}
	if out.Exists {
		out.Absent = false
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
	// Flags remember one-shot notices, e.g. which expiry date was warned
	// about. Compare keeps them; a new baseline clears them.
	Flags map[string]string `json:"flags,omitempty"`
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

// CompareOptions tune Compare.
type CompareOptions struct {
	Volatile []string // paths to ignore
	Debounce int      // consecutive observations before a change is accepted
	// Immediate, when set, accepts a change without debounce if it
	// returns true (e.g. a first registration).
	Immediate func(path string, before, after []string) bool
}

// Compare checks facts against the baseline. A difference becomes a Change
// once the same new values were seen in Debounce consecutive observations;
// the baseline then moves to the new values so the change is reported once.
// Volatile paths are ignored. A path seen for the first time is adopted
// into the baseline without a change.
func Compare(st State, facts map[string][]string, o CompareOptions) (State, []Change) {
	debounce := max(o.Debounce, 1)
	volatile := o.Volatile
	out := State{Baseline: maps.Clone(st.Baseline), Pending: maps.Clone(st.Pending), Flags: maps.Clone(st.Flags)}
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
		if p.Count < debounce && (o.Immediate == nil || !o.Immediate(path, base, now)) {
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
