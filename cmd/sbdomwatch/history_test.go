package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/sched"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeDNS returns DNS data whose A records the test can change.
type fakeDNS struct {
	now func() time.Time
	mu  sync.Mutex
	a   []string
}

func (f *fakeDNS) Name() string { return dnscheck.Name }

func (f *fakeDNS) Run(_ context.Context, _ string) (check.Observation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	vals := []dnscheck.Value{}
	for _, a := range f.a {
		vals = append(vals, dnscheck.Value{Value: a, TTL: 300})
	}
	d := dnscheck.Data{Records: map[string]dnscheck.RRSet{
		"A":  {Rcode: "NOERROR", Values: vals},
		"MX": {Rcode: "NOERROR", Values: []dnscheck.Value{}},
		"NS": {Rcode: "NOERROR", Values: []dnscheck.Value{{Value: "ns1.example.net", TTL: 86400}, {Value: "ns2.example.net", TTL: 86400}}},
	}}
	return check.NewObservation(dnscheck.Name, f.now(), d)
}

func (f *fakeDNS) setA(a ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.a = a
}

// TestPhase3AcceptanceCLI: a watch added through the CLI is observed on
// schedule and history shows the observations.
func TestPhase3AcceptanceCLI(t *testing.T) {
	e := newCLIEnv(t)
	clock := &testClock{t: time.Now().UTC().Truncate(time.Second)}
	dns := &fakeDNS{now: clock.Now, a: []string{"192.0.2.1"}}
	s := sched.New(sched.Config{
		Store: e.st, Checks: []check.Check{dns}, Log: slog.New(slog.DiscardHandler),
		Now: clock.Now, Rand: func() float64 { return 0.5 },
	})
	runOnce := func(want int) {
		t.Helper()
		n, err := s.RunOnce(t.Context())
		if err != nil || n != want {
			t.Fatalf("RunOnce = %d, %v; want %d", n, err, want)
		}
	}

	if code, out, errOut := e.run("add", "example.com", "--template", "owned", "--reason", "company domain", "--interval", "30m"); code != 0 {
		t.Fatalf("add: %d %s %s", code, out, errOut)
	}
	if _, out, _ := e.run("history", "example.com"); !strings.Contains(out, "no observations yet") {
		t.Errorf("history before first check:\n%s", out)
	}

	runOnce(1) // due immediately
	clock.Advance(29 * time.Minute)
	runOnce(0) // not due yet
	clock.Advance(time.Minute)
	runOnce(1) // due after the interval, same data
	dns.setA("192.0.2.1", "192.0.2.2")
	clock.Advance(30 * time.Minute)
	runOnce(1) // data changed

	code, out, errOut := e.run("history", "example.com")
	if code != 0 {
		t.Fatalf("history: %d %s", code, errOut)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(l, "observation") || strings.HasPrefix(l, "TIME") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 4 || !strings.Contains(out, "baseline_complete") {
		t.Fatalf("want header, 3 observations and a baseline_complete event, got:\n%s", out)
	}
	for i, want := range []string{"changed  A:2 NS:2", "same     A:1 NS:2", "first    A:1 NS:2"} {
		if !strings.Contains(lines[i+1], want) {
			t.Errorf("line %d = %q, want %q", i+1, lines[i+1], want)
		}
	}
	if !strings.Contains(lines[3], formatTime(clock.Now().Add(-time.Hour))) {
		t.Errorf("first observation time wrong: %q", lines[3])
	}

	if _, out, _ := e.run("history", "example.com", "--limit", "1", "-o", "json"); strings.Count(out, `"kind": "observation"`) != 1 {
		t.Errorf("json with limit 1:\n%s", out)
	}
	if code, _, _ := e.run("history", "nope.com"); code != exitNotFound {
		t.Errorf("missing watch exit = %d", code)
	}
	if code, _, errOut := e.run("history", "example.com", "--since", "soon"); code != exitUsage {
		t.Errorf("bad since exit = %d (%s)", code, errOut)
	}
}

func TestEventsCLI(t *testing.T) {
	e := newCLIEnv(t)
	clock := &testClock{t: time.Now().UTC().Truncate(time.Second)}
	dns := &fakeDNS{now: clock.Now, a: []string{"192.0.2.1"}}
	s := sched.New(sched.Config{
		Store: e.st, Checks: []check.Check{dns}, Log: slog.New(slog.DiscardHandler),
		Extractors: map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts},
		Lifecycle:  watch.LifecycleConfig{BaselineObservations: 1, Debounce: 1},
		Now:        clock.Now, Rand: func() float64 { return 0.5 },
	})
	if code, _, errOut := e.run("add", "example.com", "--template", "owned", "--reason", "x"); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	dns.setA("192.0.2.9")
	clock.Advance(time.Hour)
	if _, err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := e.run("events", "--since", "")
	if code != 0 {
		t.Fatalf("events: %d %s", code, errOut)
	}
	for _, want := range []string{"record_changed", "dns.A +192.0.2.9 -192.0.2.1", "baseline_complete", "1 observation(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("events output lacks %q:\n%s", want, out)
		}
	}
	if _, out, _ := e.run("events", "--since", "", "--type", "baseline_complete", "-o", "json"); strings.Count(out, `"type": "baseline_complete"`) != 1 || strings.Contains(out, "record_changed") {
		t.Errorf("type filter:\n%s", out)
	}
	if _, out, _ := e.run("events", "--since", "", "--severity", "high"); !strings.Contains(out, "no events") {
		t.Errorf("severity filter:\n%s", out)
	}
	if code, _, _ := e.run("events", "--type", "nope"); code != exitUsage {
		t.Errorf("bad type exit = %d", code)
	}
}
