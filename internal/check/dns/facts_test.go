package dns

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestFacts(t *testing.T) {
	data := Data{Records: map[string]RRSet{
		"A":   {Rcode: "NOERROR", Values: []Value{{"192.0.2.2", 60}, {"192.0.2.1", 300}}},
		"MX":  {Rcode: "NOERROR", Values: []Value{}},
		"NS":  {Values: []Value{}, Error: "timeout"},
		"SOA": {Rcode: "NOERROR", Values: []Value{{"ns1.example.net hostmaster.example.com 2026112301 7200 3600 1209600 300", 3600}}},
		"TXT": {Rcode: "FORMERR", Values: []Value{}},
	}}
	raw, _ := json.Marshal(data)
	f, err := Facts(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"dns.A":   {"192.0.2.1", "192.0.2.2"},
		"dns.MX":  {},
		"dns.SOA": {"ns1.example.net hostmaster.example.com"},
	}
	if len(f.Values) != len(want) {
		t.Errorf("paths = %v, want %v (NS failed and TXT FORMERR are unknown)", f.Values, want)
	}
	for k, v := range want {
		if !slices.Equal(f.Values[k], v) {
			t.Errorf("%s = %v, want %v", k, f.Values[k], v)
		}
	}
	if f.Absent {
		t.Error("absent for an existing domain")
	}

	// TTL changes alone give identical facts.
	data.Records["A"] = RRSet{Rcode: "NOERROR", Values: []Value{{"192.0.2.1", 12}, {"192.0.2.2", 7}}}
	raw2, _ := json.Marshal(data)
	f2, _ := Facts(raw2)
	if !slices.Equal(f.Values["dns.A"], f2.Values["dns.A"]) {
		t.Error("TTL change altered facts")
	}
}

func TestFactsAbsent(t *testing.T) {
	all := map[string]RRSet{}
	for _, typ := range Types {
		all[TypeName(typ)] = RRSet{Rcode: "NXDOMAIN", Values: []Value{}}
	}
	raw, _ := json.Marshal(Data{Records: all})
	f, _ := Facts(raw)
	if !f.Absent || len(f.Values["dns.NS"]) != 0 {
		t.Errorf("facts = %+v, want absent", f)
	}

	all["MX"] = RRSet{Values: []Value{}, Error: "timeout"}
	raw, _ = json.Marshal(Data{Records: all})
	if f, _ := Facts(raw); f.Absent {
		t.Error("absent although one type is unknown")
	}

	if _, err := Facts(json.RawMessage(`{`)); err == nil {
		t.Error("want error for bad JSON")
	}
}

func TestFactsDangling(t *testing.T) {
	cname := func(rc string, vals ...string) RRSet {
		s := RRSet{Rcode: rc, Values: []Value{}}
		for _, v := range vals {
			s.Values = append(s.Values, Value{Value: v, TTL: 300})
		}
		return s
	}
	tests := []struct {
		name    string
		rec     map[string]RRSet
		want    []string
		unknown bool
	}{
		{"no cname", map[string]RRSet{"CNAME": cname("NOERROR"), "A": cname("NOERROR", "1.2.3.4"), "AAAA": cname("NOERROR")}, []string{}, false},
		{"cname resolves", map[string]RRSet{"CNAME": cname("NOERROR", "app.herokudns.com"), "A": cname("NOERROR", "1.2.3.4"), "AAAA": cname("NOERROR")}, []string{}, false},
		{"cname target gone", map[string]RRSet{"CNAME": cname("NOERROR", "old-app.herokudns.com"), "A": cname("NXDOMAIN"), "AAAA": cname("NXDOMAIN")}, []string{"old-app.herokudns.com"}, false},
		{"only A nxdomain", map[string]RRSet{"CNAME": cname("NOERROR", "x.example"), "A": cname("NXDOMAIN"), "AAAA": cname("NOERROR")}, []string{}, false},
		{"A lookup failed", map[string]RRSet{"CNAME": cname("NOERROR", "x.example"), "A": {Error: "timeout"}, "AAAA": cname("NXDOMAIN")}, nil, true},
		{"cname lookup failed", map[string]RRSet{"CNAME": {Error: "timeout"}, "A": cname("NXDOMAIN"), "AAAA": cname("NXDOMAIN")}, nil, true},
		{"name itself nxdomain", map[string]RRSet{"CNAME": cname("NXDOMAIN"), "A": cname("NXDOMAIN"), "AAAA": cname("NXDOMAIN")}, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(Data{Records: tt.rec})
			f, err := Facts(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := f.Values["dns.dangling"]
			if ok == tt.unknown || (!tt.unknown && !slices.Equal(got, tt.want)) {
				t.Errorf("dns.dangling = %v (known %v), want %v (unknown %v)", got, ok, tt.want, tt.unknown)
			}
		})
	}
}
