package sched

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	dprdap "github.com/sbroekhoven/domping/rdap"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	rdapcheck "github.com/sbroekhoven/sbdomwatch/internal/check/rdap"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// registrationDNS answers NXDOMAIN until the domain is registered.
type registrationDNS struct {
	now  func() time.Time
	live *atomic.Bool
}

func (r *registrationDNS) Name() string { return dnscheck.Name }

func (r *registrationDNS) Run(_ context.Context, _ string) (check.Observation, error) {
	rec := map[string]dnscheck.RRSet{}
	for _, t := range dnscheck.Types {
		rec[dnscheck.TypeName(t)] = dnscheck.RRSet{Rcode: "NXDOMAIN", Values: []dnscheck.Value{}}
	}
	if r.live.Load() {
		for _, t := range dnscheck.Types {
			rec[dnscheck.TypeName(t)] = dnscheck.RRSet{Rcode: "NOERROR", Values: []dnscheck.Value{}}
		}
		rec["NS"] = dnscheck.RRSet{Rcode: "NOERROR", Values: []dnscheck.Value{{Value: "ns1.parking.example", TTL: 300}}}
		rec["A"] = dnscheck.RRSet{Rcode: "NOERROR", Values: []dnscheck.Value{{Value: "192.0.2.66", TTL: 300}}}
	}
	return check.NewObservation(dnscheck.Name, r.now(), dnscheck.Data{Records: rec})
}

// TestPhase5RegistrationAcceptance: a watch on an unregistered domain fires
// registered once it exists, through the real RDAP check and domping's
// client against a fake registry.
func TestPhase5RegistrationAcceptance(t *testing.T) {
	var live atomic.Bool
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !live.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"objectClassName":"domain","ldhName":"degir0.com","status":["client transfer prohibited"],
			"nameservers":[{"ldhName":"ns1.parking.example"}],
			"entities":[{"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"1068"}],
			  "vcardArray":["vcard",[["fn",{},"text","Cheap Names Ltd"]]]}]}`)
	}))
	defer registry.Close()
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"services": [[["com"], [%q]]]}`, registry.URL+"/")
	}))
	defer bootstrap.Close()
	client := dprdap.New(dprdap.Options{BootstrapURL: bootstrap.URL, Timeout: time.Second, MaxAttempts: 1})

	e := newEnv(t, 1)
	e.s = New(Config{
		Store:  e.st,
		Checks: []check.Check{&registrationDNS{now: e.clock.Now, live: &live}, rdapcheck.New(client, e.clock.Now)},
		Extractors: map[string]diff.Extractor{
			dnscheck.Name:  dnscheck.Facts,
			rdapcheck.Name: rdapcheck.Facts,
		},
		Lifecycle: watch.LifecycleConfig{BaselineObservations: 3, Debounce: 2},
		Log:       slog.New(slog.DiscardHandler), Workers: 1, Now: e.clock.Now, Rand: func() float64 { return 0.5 },
	})
	r, _ := watch.AddRequest{Domain: "degir0.com", Template: watch.TemplateCandidate, Reason: "typosquat of degiro", Origin: watch.OriginTyposquat}.Normalize()
	if _, err := e.st.AddWatch(t.Context(), r, "sbsquat", watch.Defaults{Intervals: map[watch.Template]time.Duration{watch.TemplateCandidate: time.Hour}, CandidateTTL: 90 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	step := func() {
		t.Helper()
		if n := e.runOnce(t); n != 1 {
			t.Fatalf("claimed %d", n)
		}
		w, _ := e.st.GetWatch(t.Context(), "degir0.com")
		e.clock.Advance(w.NextCheckAt.Sub(e.clock.Now()))
	}
	types := func() []string {
		evs := e.timeline(t, "degir0.com", "event")
		slices.Reverse(evs)
		var out []string
		for _, ev := range evs {
			out = append(out, ev.Type)
		}
		return out
	}

	step() // unregistered: baselines after a single observation
	if w, _ := e.st.GetWatch(t.Context(), "degir0.com"); w.State != watch.StateActive {
		t.Fatalf("state after first check = %s, want active", w.State)
	}
	step()
	step()
	if got := types(); !slices.Equal(got, []string{"baseline_complete"}) {
		t.Fatalf("before registration: %v", got)
	}

	live.Store(true)
	step() // registered fires at the first sighting
	got := types()
	if !slices.Equal(got, []string{"baseline_complete", "registered"}) {
		t.Fatalf("after registration: %v", got)
	}
	evs := e.timeline(t, "degir0.com", "event")
	var p events.Payload
	if err := jsonUnmarshal(evs[0].Data, &p); err != nil {
		t.Fatal(err)
	}
	if evs[0].Severity != "high" || len(p.Details) != 3 || p.Origins[0].Origin != "typosquat" {
		t.Errorf("registered event = %s %+v", evs[0].Severity, p)
	}

	step() // DNS confirms with debounce: NS and A appear
	step()
	got = types()
	want := []string{"baseline_complete", "registered", "record_added", "record_added"}
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if n := slices.Index(got, "registered"); slices.Index(got[n+1:], "registered") >= 0 {
		t.Error("registered fired twice")
	}
}
