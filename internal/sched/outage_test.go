package sched

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// receiver is a webhook endpoint that can be taken down.
type receiver struct {
	mu   sync.Mutex
	up   bool
	hits int
	got  []events.Event
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	if !r.up {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var e events.Event
	b, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(b, &e); err == nil {
		r.got = append(r.got, e)
	}
}

func (r *receiver) set(up bool) { r.mu.Lock(); defer r.mu.Unlock(); r.up = up }

func (r *receiver) snapshot() (int, []events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits, append([]events.Event(nil), r.got...)
}

// TestPhase5OutageAcceptance: events survive a webhook outage, including a
// restart of the service during the outage, and are delivered afterwards,
// each exactly once and in order.
func TestPhase5OutageAcceptance(t *testing.T) {
	rcv := &receiver{}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	clock := &fakeClock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	dbPath := filepath.Join(t.TempDir(), "outage.db")
	log := slog.New(slog.DiscardHandler)

	open := func() (*store.Store, *events.Dispatcher, *Scheduler) {
		st, err := store.Open(t.Context(), dbPath, store.Options{Now: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		sinks := []events.Sink{events.NewWebhook(srv.URL, "secret", events.Info, srv.Client(), "test")}
		disp := events.NewDispatcher(events.DispatcherConfig{Store: st, Sinks: sinks, Log: log, Now: clock.Now, Rand: func() float64 { return 0.5 }})
		sc := New(Config{
			Store: st, Checks: []check.Check{&noisyDNS{now: clock.Now, mxFrom: 4}},
			Extractors: map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts},
			Lifecycle:  watch.LifecycleConfig{BaselineObservations: 3, Debounce: 2},
			Route:      events.Router(sinks), Log: log, Workers: 1, Now: clock.Now, Rand: func() float64 { return 0.5 },
		})
		return st, disp, sc
	}

	st, disp, sc := open()
	r, _ := watch.AddRequest{Domain: "example.com", Template: watch.TemplateOwned, Reason: "outage test"}.Normalize()
	if _, err := st.AddWatch(t.Context(), r, "seb", watch.Defaults{Intervals: map[watch.Template]time.Duration{watch.TemplateOwned: time.Hour}}); err != nil {
		t.Fatal(err)
	}

	// The webhook is down while the baseline completes and the MX appears.
	for range 7 {
		if _, err := sc.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := disp.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		w, _ := st.GetWatch(t.Context(), "example.com")
		clock.Advance(w.NextCheckAt.Sub(clock.Now()))
	}
	hits, got := rcv.snapshot()
	if hits == 0 || len(got) != 0 {
		t.Fatalf("during outage: %d attempts, %d delivered; want attempts and nothing delivered", hits, len(got))
	}
	stats, _ := st.OutboxStats(t.Context())
	if stats["webhook"] != 2 {
		t.Fatalf("outbox holds %v, want 2 pending (baseline_complete, mx_appeared)", stats)
	}

	// Restart during the outage: the outbox is in SQLite, not in memory.
	st.Close()
	st, disp, _ = open()
	defer st.Close()

	rcv.set(true)
	clock.Advance(2 * time.Hour) // past any backoff
	for range 3 {
		if _, err := disp.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	_, got = rcv.snapshot()
	if len(got) != 2 || got[0].Type != events.BaselineComplete || got[1].Type != events.MXAppeared {
		t.Fatalf("delivered after recovery: %+v", got)
	}
	if got[1].Payload.Domain != "example.com" || got[1].Payload.Change == nil || got[1].Payload.Change.Added[0] != "10 mail.example.com" {
		t.Errorf("mx_appeared payload = %+v", got[1].Payload)
	}
	if stats, _ := st.OutboxStats(t.Context()); len(stats) != 0 {
		t.Errorf("outbox not empty after delivery: %v", stats)
	}
}
