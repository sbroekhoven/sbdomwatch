package sched

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// noisyDNS simulates a real-world domain through the actual DNS data format:
//   - round-robin A records: each answer is 2 of a pool of 4, rotating;
//   - TTLs that change on every answer;
//   - a flapping resolver: every 5th answer (from round 3) fails for MX
//     with SERVFAIL, one answer returns a lame NS set, one an empty TXT;
//   - one real change: an MX record appears from round mxFrom onwards.
type noisyDNS struct {
	now    func() time.Time
	mxFrom int

	mu    sync.Mutex
	round int
}

func (n *noisyDNS) Name() string { return dnscheck.Name }

func (n *noisyDNS) Run(_ context.Context, _ string) (check.Observation, error) {
	n.mu.Lock()
	i := n.round
	n.round++
	n.mu.Unlock()

	ttl := func(base int) uint32 { return uint32(base - (i*37)%base) }
	val := func(base int, vs ...string) []dnscheck.Value {
		out := []dnscheck.Value{}
		for _, v := range vs {
			out = append(out, dnscheck.Value{Value: v, TTL: ttl(base)})
		}
		return out
	}
	ok := func(vs []dnscheck.Value) dnscheck.RRSet { return dnscheck.RRSet{Rcode: "NOERROR", Values: vs} }

	pool := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	rec := map[string]dnscheck.RRSet{
		"A":     ok(val(60, pool[i%4], pool[(i+1)%4])),
		"AAAA":  ok(val(300)),
		"CNAME": ok(val(300)),
		"MX":    ok(val(3600)),
		"NS":    ok(val(86400, "ns1.example.net", "ns2.example.net")),
		"TXT":   ok(val(300, "v=spf1 -all")),
		"CAA":   ok(val(300)),
		"SOA":   ok(val(3600, "ns1.example.net hostmaster.example.com "+string(rune('0'+i%10))+" 7200 3600 1209600 300")),
	}
	if i >= n.mxFrom {
		rec["MX"] = ok(val(3600, "10 mail.example.com"))
	}
	if i >= 3 && i%5 == 3 {
		rec["MX"] = dnscheck.RRSet{Values: []dnscheck.Value{}, Error: "9.9.9.9:53: SERVFAIL"}
	}
	switch i {
	case 1:
		rec["MX"] = dnscheck.RRSet{Values: []dnscheck.Value{}, Error: "i/o timeout"} // flap during baseline
	case 6:
		rec["NS"] = ok(val(60, "ns.lame-delegation.example"))
	case 9:
		rec["TXT"] = ok(val(300))
	}
	return check.NewObservation(dnscheck.Name, n.now(), dnscheck.Data{Records: rec})
}

// TestPhase4Acceptance: round-robin A records, TTL changes, a flapping
// resolver and one real MX addition yield exactly one change event,
// mx_appeared (after the baseline_complete event that ends baselining).
func TestPhase4Acceptance(t *testing.T) {
	e := newEnv(t, 1)
	dns := &noisyDNS{now: e.clock.Now, mxFrom: 12}
	e.s = New(Config{
		Store:       e.st,
		Checks:      []check.Check{dns},
		Extractors:  map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts},
		Lifecycle:   watch.LifecycleConfig{BaselineObservations: 3, Debounce: 2},
		BaselineGap: 3 * time.Minute,
		Log:         slog.New(slog.DiscardHandler),
		Workers:     1,
		Now:         e.clock.Now,
		Rand:        func() float64 { return 0.5 },
	})
	e.add(t, "example.com", time.Hour)

	const rounds = 25
	for r := range rounds {
		if n := e.runOnce(t); n != 1 {
			t.Fatalf("round %d: claimed %d", r, n)
		}
		w, _ := e.st.GetWatch(t.Context(), "example.com")
		gap := w.NextCheckAt.Sub(e.clock.Now())
		if r < 2 && (w.State != watch.StateBaselining || gap != 3*time.Minute) {
			t.Fatalf("round %d: state %s, next in %v; want baselining, 3m", r, w.State, gap)
		}
		if r >= 2 && (w.State != watch.StateActive || gap != time.Hour) {
			t.Fatalf("round %d: state %s, next in %v; want active, 1h", r, w.State, gap)
		}
		e.clock.Advance(gap)
	}

	w, _ := e.st.GetWatch(t.Context(), "example.com")
	if w.State != watch.StateActive || !slices.Equal(w.VolatileFields, []string{"dns.A"}) {
		t.Fatalf("watch = state %s, volatile %v; want active, [dns.A]", w.State, w.VolatileFields)
	}
	if got := len(e.history(t, "example.com")); got != rounds {
		t.Errorf("%d observations, want %d", got, rounds)
	}

	evs := e.timeline(t, "example.com", "event")
	slices.Reverse(evs) // oldest first
	var types []string
	for _, ev := range evs {
		types = append(types, ev.Type)
	}
	want := []string{string(events.BaselineComplete), string(events.MXAppeared)}
	if !slices.Equal(types, want) {
		t.Fatalf("events = %v, want %v", types, want)
	}
	mx := evs[1]
	if mx.Severity != string(events.High) {
		t.Errorf("mx_appeared severity = %s", mx.Severity)
	}
	// Round 12 has the MX, round 13 is a resolver failure (unknown), round 14
	// confirms it: the event fires at round 14, not before.
	baselineEnd := evs[0].At
	if want := baselineEnd.Add(time.Hour * 12); !mx.At.Equal(want) {
		t.Errorf("mx_appeared at %v, want %v (round 14)", mx.At, want)
	}

	var p events.Payload
	if err := jsonUnmarshal(mx.Data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Change == nil || p.Change.Path != "dns.MX" || !slices.Equal(p.Change.Added, []string{"10 mail.example.com"}) ||
		p.Domain != "example.com" || len(p.Origins) != 1 || p.Origins[0].Reason != "test" {
		t.Errorf("mx_appeared payload = %+v", p)
	}

	var inv events.Payload
	if err := jsonUnmarshal(evs[0].Data, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Observations != 3 || !slices.Equal(inv.Inventory["dns.NS"], []string{"ns1.example.net", "ns2.example.net"}) ||
		!slices.Equal(inv.Inventory["dns.SOA"], []string{"ns1.example.net hostmaster.example.com"}) {
		t.Errorf("baseline inventory = %+v", inv)
	}

	base := e.timeline(t, "example.com", "observation")
	nBaseline := 0
	for _, o := range base {
		if o.Baseline {
			nBaseline++
		}
	}
	if nBaseline != 3 {
		t.Errorf("%d baseline observations, want 3", nBaseline)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// TestPhase4NoiseIsReal is the control for TestPhase4Acceptance: without
// debounce the same simulation must produce noise events, otherwise the
// acceptance test would prove nothing.
func TestPhase4NoiseIsReal(t *testing.T) {
	e := newEnv(t, 1)
	e.s = New(Config{
		Store:      e.st,
		Checks:     []check.Check{&noisyDNS{now: e.clock.Now, mxFrom: 12}},
		Extractors: map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts},
		Lifecycle:  watch.LifecycleConfig{BaselineObservations: 3, Debounce: 1},
		Log:        slog.New(slog.DiscardHandler),
		Workers:    1,
		Now:        e.clock.Now,
		Rand:       func() float64 { return 0.5 },
	})
	e.add(t, "example.com", time.Hour)
	for range 25 {
		e.runOnce(t)
		w, _ := e.st.GetWatch(t.Context(), "example.com")
		e.clock.Advance(w.NextCheckAt.Sub(e.clock.Now()))
	}
	got := map[string]int{}
	for _, ev := range e.timeline(t, "example.com", "event") {
		got[ev.Type]++
	}
	if got[string(events.NSChanged)] != 2 || got[string(events.RecordRemoved)] != 1 || got[string(events.RecordAdded)] != 1 {
		t.Errorf("without debounce want 2 ns_changed (flap and back) and a TXT remove/add pair, got %v", got)
	}
}
