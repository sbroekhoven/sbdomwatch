package present

import (
	"encoding/json"
	"testing"
	"time"

	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	rdapcheck "github.com/sbroekhoven/sbdomwatch/internal/check/rdap"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
)

func obs(t *testing.T, check, hash string, data any) store.TimelineEntry {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return store.TimelineEntry{Kind: "observation", Check: check, Hash: hash, Data: b}
}

func TestChange(t *testing.T) {
	entries := []store.TimelineEntry{
		{Kind: "observation", Check: "dns", Hash: "b"},
		{Kind: "event", Type: "mx_appeared"},
		{Kind: "observation", Check: "rdap", Hash: "x"},
		{Kind: "observation", Check: "dns", Hash: "a"},
		{Kind: "observation", Check: "dns", Hash: "a"},
	}
	want := map[int]string{0: "changed", 2: "first", 3: "same", 4: "first"}
	for i, w := range want {
		if got := Change(entries, i); got != w {
			t.Errorf("Change(%d) = %s, want %s", i, got, w)
		}
	}
}

func TestObservation(t *testing.T) {
	exp := time.Date(2027, 8, 13, 0, 0, 0, 0, time.UTC)
	dns := dnscheck.Data{Records: map[string]dnscheck.RRSet{
		"A":   {Rcode: "NOERROR", Values: []dnscheck.Value{{Value: "1.2.3.4"}, {Value: "1.2.3.5"}}},
		"MX":  {Rcode: "NOERROR", Values: []dnscheck.Value{}},
		"NS":  {Error: "timeout"},
		"TXT": {Rcode: "NXDOMAIN", Values: []dnscheck.Value{}},
	}}
	tests := []struct {
		name string
		e    store.TimelineEntry
		want string
	}{
		{"dns", obs(t, "dns", "h", dns), "A:2 NS:error TXT:NXDOMAIN"},
		{"dns empty", obs(t, "dns", "h", dnscheck.Data{}), "no records"},
		{"rdap registered", obs(t, "rdap", "h", rdapcheck.Data{State: "registered", Registrar: "MarkMonitor Inc.", Nameservers: []string{"a", "b"}, Expiry: &exp}), "registered MarkMonitor Inc. NS:2 expires 2027-08-13"},
		{"rdap free", obs(t, "rdap", "h", rdapcheck.Data{State: "not-registered"}), "not-registered"},
		{"unknown check", store.TimelineEntry{Check: "http", Hash: "0123456789abcdef"}, "hash 0123456789ab"},
		{"bad data", store.TimelineEntry{Check: "dns", Data: json.RawMessage("{")}, "unreadable data"},
	}
	for _, tt := range tests {
		if got := Observation(tt.e); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestEventDetail(t *testing.T) {
	exp := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		e    events.Event
		want string
	}{
		{events.Event{Type: events.RecordChanged, Payload: events.Payload{Change: &diff.Change{Path: "dns.A", Added: []string{"2"}, Removed: []string{"1"}}}}, "dns.A +2 -1"},
		{events.Event{Type: events.BaselineComplete, Payload: events.Payload{Observations: 3, Inventory: map[string][]string{"a": {}}, VolatileFields: []string{"dns.A"}}}, "3 observation(s), 1 fields, volatile dns.A"},
		{events.Event{Type: events.Expiring, Payload: events.Payload{Expiry: &exp}}, "expires 2027-01-02"},
		{events.Event{Type: events.Registered}, "-"},
	}
	for _, tt := range tests {
		if got := EventDetail(tt.e); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.e.Type, got, tt.want)
		}
	}
}
