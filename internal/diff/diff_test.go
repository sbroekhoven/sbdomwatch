package diff

import (
	"slices"
	"testing"
)

type m = map[string][]string

func TestSet(t *testing.T) {
	if got := Set([]string{"b", "a", "b"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Set = %v", got)
	}
	if got := Set(nil); got == nil || len(got) != 0 {
		t.Errorf("Set(nil) = %#v, want empty non-nil", got)
	}
}

func TestMerge(t *testing.T) {
	f := Merge(Facts{Values: m{"dns.A": {"1"}}}, Facts{Values: m{"rdap.status": {"x"}}, Absent: true})
	if len(f.Values) != 2 || !f.Absent {
		t.Errorf("Merge = %+v", f)
	}
	// RDAP says registered: DNS NXDOMAIN does not make it absent.
	if f := Merge(Facts{Absent: true}, Facts{Exists: true}); f.Absent || !f.Exists {
		t.Errorf("Exists must override Absent: %+v", f)
	}
}

func TestLearn(t *testing.T) {
	tests := []struct {
		name         string
		samples      []map[string][]string
		wantBaseline m
		wantVolatile []string
	}{
		{
			name:         "stable",
			samples:      []map[string][]string{{"a": {"1"}}, {"a": {"1"}}, {"a": {"1"}}},
			wantBaseline: m{"a": {"1"}},
			wantVolatile: []string{},
		},
		{
			name:         "order and duplicates do not matter",
			samples:      []map[string][]string{{"a": {"2", "1"}}, {"a": {"1", "2", "2"}}},
			wantBaseline: m{"a": {"1", "2"}},
			wantVolatile: []string{},
		},
		{
			name:         "round robin is volatile, latest value kept",
			samples:      []map[string][]string{{"a": {"1", "2"}, "b": {"x"}}, {"a": {"3", "4"}, "b": {"x"}}, {"a": {"1", "2"}, "b": {"x"}}},
			wantBaseline: m{"a": {"1", "2"}, "b": {"x"}},
			wantVolatile: []string{"a"},
		},
		{
			name:         "unknown in one sample is not volatile",
			samples:      []map[string][]string{{"a": {"1"}, "b": {"x"}}, {"b": {"x"}}, {"a": {"1"}, "b": {"x"}}},
			wantBaseline: m{"a": {"1"}, "b": {"x"}},
			wantVolatile: []string{},
		},
		{
			name:         "single sample",
			samples:      []map[string][]string{{"a": {}}},
			wantBaseline: m{"a": {}},
			wantVolatile: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, v := Learn(tt.samples)
			if !equalMaps(b, tt.wantBaseline) || !slices.Equal(v, tt.wantVolatile) {
				t.Errorf("Learn = %v %v, want %v %v", b, v, tt.wantBaseline, tt.wantVolatile)
			}
		})
	}
}

func equalMaps(a, b m) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !slices.Equal(v, w) {
			return false
		}
	}
	return true
}

func TestCompareDebounce(t *testing.T) {
	st := State{Baseline: m{"dns.MX": {}, "dns.NS": {"ns1", "ns2"}, "dns.A": {"1"}}}
	steps := []struct {
		name  string
		facts m
		want  []string // "path:kind" of accepted changes
	}{
		{"same", m{"dns.MX": {}, "dns.NS": {"ns2", "ns1"}, "dns.A": {"9"}}, nil},
		{"one-off NS flap", m{"dns.MX": {}, "dns.NS": {"lame"}}, nil},
		{"back to normal resets pending", m{"dns.MX": {}, "dns.NS": {"ns1", "ns2"}}, nil},
		{"MX appears once", m{"dns.MX": {"10 mx"}, "dns.NS": {"ns1", "ns2"}}, nil},
		{"MX unknown keeps pending", m{"dns.NS": {"ns1", "ns2"}}, nil},
		{"MX seen again: accepted", m{"dns.MX": {"10 mx"}, "dns.NS": {"ns1", "ns2"}}, []string{"dns.MX:added"}},
		{"MX stays: no repeat", m{"dns.MX": {"10 mx"}, "dns.NS": {"ns1", "ns2"}}, nil},
		{"new path adopted silently", m{"dns.TXT": {"v=spf1"}}, nil},
		{"NS changes twice in a row", m{"dns.NS": {"evil1"}}, nil},
		{"NS accepted", m{"dns.NS": {"evil1"}}, []string{"dns.NS:changed"}},
		{"MX removed", m{"dns.MX": {}}, nil},
		{"MX removed accepted", m{"dns.MX": {}}, []string{"dns.MX:removed"}},
	}
	for _, s := range steps {
		var changes []Change
		st, changes = Compare(st, s.facts, CompareOptions{Volatile: []string{"dns.A"}, Debounce: 2})
		var got []string
		for _, c := range changes {
			got = append(got, c.Path+":"+string(c.Kind))
		}
		if !slices.Equal(got, s.want) {
			t.Fatalf("%s: changes = %v, want %v (state %+v)", s.name, got, s.want, st)
		}
	}
	if !slices.Equal(st.Baseline["dns.NS"], []string{"evil1"}) || !slices.Equal(st.Baseline["dns.TXT"], []string{"v=spf1"}) {
		t.Errorf("baseline = %v", st.Baseline)
	}
	if _, ok := st.Baseline["dns.A"]; !ok {
		t.Error("volatile path dropped from baseline")
	}
}

func TestCompareChangeDetail(t *testing.T) {
	st := State{Baseline: m{"dns.A": {"1", "2"}}}
	_, ch := Compare(st, m{"dns.A": {"2", "3"}}, CompareOptions{Debounce: 1})
	if len(ch) != 1 {
		t.Fatalf("changes = %v", ch)
	}
	c := ch[0]
	if c.Kind != Changed || !slices.Equal(c.Added, []string{"3"}) || !slices.Equal(c.Removed, []string{"1"}) ||
		!slices.Equal(c.Before, []string{"1", "2"}) || !slices.Equal(c.After, []string{"2", "3"}) {
		t.Errorf("change = %+v", c)
	}
}

func TestCompareDoesNotModifyInput(t *testing.T) {
	st := State{Baseline: m{"a": {"1"}}, Pending: map[string]Pending{"a": {Values: []string{"2"}, Count: 1}}}
	Compare(st, m{"a": {"2"}}, CompareOptions{Debounce: 2})
	if st.Pending["a"].Count != 1 || st.Baseline["a"][0] != "1" {
		t.Errorf("input modified: %+v", st)
	}
}

func TestCompareImmediate(t *testing.T) {
	st := State{Baseline: m{"rdap.registered": {"false"}, "dns.NS": {"a"}}}
	imm := func(path string, before, after []string) bool {
		return path == "rdap.registered" && slices.Equal(after, []string{"true"})
	}
	st, ch := Compare(st, m{"rdap.registered": {"true"}, "dns.NS": {"b"}}, CompareOptions{Debounce: 2, Immediate: imm})
	if len(ch) != 1 || ch[0].Path != "rdap.registered" {
		t.Fatalf("changes = %+v, want only the immediate one", ch)
	}
	if _, pending := st.Pending["dns.NS"]; !pending {
		t.Error("other paths must still be debounced")
	}
}
