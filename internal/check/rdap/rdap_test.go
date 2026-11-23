package rdap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dprdap "github.com/sbroekhoven/domping/rdap"
)

const registered = `{
  "objectClassName": "domain", "ldhName": "example.test",
  "status": ["client transfer prohibited", "active"],
  "events": [
    {"eventAction": "registration", "eventDate": "2001-02-03T04:05:06Z"},
    {"eventAction": "expiration", "eventDate": "2027-02-03T04:05:06Z"}
  ],
  "nameservers": [{"ldhName": "NS2.Example.NET"}, {"ldhName": "ns1.example.net."}],
  "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
    "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]}]
}`

// registry is a fake RDAP server for the "test" TLD with a bootstrap file.
type registry struct {
	mu     sync.Mutex
	status int
	body   string
	paths  []string
}

func (r *registry) set(status int, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status, r.body = status, body
}

func newClient(t *testing.T, r *registry) *dprdap.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.paths = append(r.paths, req.URL.Path)
		w.WriteHeader(r.status)
		fmt.Fprint(w, r.body)
	}))
	t.Cleanup(srv.Close)
	bs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"services": [[["test"], [%q]]]}`, srv.URL+"/")
	}))
	t.Cleanup(bs.Close)
	// Domains outside .test go to the fallback, which says "no RDAP service".
	fb := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(fb.Close)
	return dprdap.New(dprdap.Options{BootstrapURL: bs.URL, FallbackURL: fb.URL + "/domain/", Timeout: time.Second, MaxAttempts: 1})
}

func TestRun(t *testing.T) {
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		domain    string
		status    int
		body      string
		wantState string
		wantErr   bool
		wantPath  string
	}{
		{"registered", "example.test", 200, registered, StateRegistered, false, "/domain/example.test"},
		{"subdomain looks up registrable domain", "mail.example.test", 200, registered, StateRegistered, false, "/domain/example.test"},
		{"not registered", "free.test", 404, `{"errorCode":404}`, StateNotRegistered, false, "/domain/free.test"},
		{"server error is unknown", "example.test", 503, "", "", true, "/domain/example.test"},
		{"tld without rdap", "example.zz", 0, "", StateNoService, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &registry{}
			r.set(tt.status, tt.body)
			c := New(newClient(t, r), func() time.Time { return at })
			obs, err := c.Run(t.Context(), tt.domain)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %s", obs.Data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var d Data
			if err := json.Unmarshal(obs.Data, &d); err != nil {
				t.Fatal(err)
			}
			if d.State != tt.wantState || obs.Check != Name || !obs.ObservedAt.Equal(at) {
				t.Errorf("observation = %+v %+v", obs, d)
			}
			if tt.wantPath != "" && (len(r.paths) != 1 || r.paths[0] != tt.wantPath) {
				t.Errorf("requests = %v, want %s", r.paths, tt.wantPath)
			}
			if tt.wantState == StateRegistered {
				if d.Registrar != "MarkMonitor Inc." || d.RegistrarIANAID != "292" ||
					!slices.Equal(d.Nameservers, []string{"ns1.example.net", "ns2.example.net"}) ||
					!slices.Equal(d.Statuses, []string{"active", "clientTransferProhibited"}) ||
					d.Registered == nil || d.Expiry == nil {
					t.Errorf("data = %+v", d)
				}
			}
		})
	}
}

func TestFacts(t *testing.T) {
	enc := func(d Data) json.RawMessage { b, _ := json.Marshal(d); return b }
	tests := []struct {
		name   string
		data   Data
		want   map[string][]string
		exists bool
		absent bool
	}{
		{
			name:   "registered with IANA id",
			data:   Data{State: StateRegistered, Registrar: "MarkMonitor Inc.", RegistrarIANAID: "292", Nameservers: []string{"b", "a"}, Statuses: []string{"active"}},
			want:   map[string][]string{"rdap.registered": {"true"}, "rdap.registrar": {"iana:292"}, "rdap.nameservers": {"a", "b"}, "rdap.status": {"active"}},
			exists: true,
		},
		{
			name:   "registrar name only",
			data:   Data{State: StateRegistered, Registrar: "  Some   Registrar  BV "},
			want:   map[string][]string{"rdap.registered": {"true"}, "rdap.registrar": {"name:some registrar bv"}, "rdap.nameservers": {}, "rdap.status": {}},
			exists: true,
		},
		{
			name:   "not registered",
			data:   Data{State: StateNotRegistered},
			want:   map[string][]string{"rdap.registered": {"false"}, "rdap.registrar": {}, "rdap.nameservers": {}, "rdap.status": {}},
			absent: true,
		},
		{
			name: "no rdap service says nothing",
			data: Data{State: StateNoService},
			want: map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Facts(enc(tt.data))
			if err != nil {
				t.Fatal(err)
			}
			if f.Exists != tt.exists || f.Absent != tt.absent || len(f.Values) != len(tt.want) {
				t.Fatalf("facts = %+v", f)
			}
			for k, v := range tt.want {
				if !slices.Equal(f.Values[k], v) {
					t.Errorf("%s = %v, want %v", k, f.Values[k], v)
				}
			}
		})
	}
	if _, err := Facts(json.RawMessage("{")); err == nil || !strings.Contains(err.Error(), "rdap facts") {
		t.Errorf("bad json: %v", err)
	}
}
