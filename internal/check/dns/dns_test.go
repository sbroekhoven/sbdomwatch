package dns

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// fakeServer is a local DNS server on 127.0.0.1 (UDP and TCP, same port).
type fakeServer struct {
	addr string

	mu       sync.Mutex
	zone     map[string][]string // "name TYPE" -> RRs in zone-file syntax
	rcode    map[uint16]int      // forced rcode per query type
	truncate bool                // set TC on UDP answers
	queries  int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{zone: map[string][]string{}, rcode: map[uint16]int{}}
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc = nil
	}
	if pc == nil {
		t.Fatal("could not get matching UDP and TCP ports")
	}
	f.addr = pc.LocalAddr().String()
	udp := &mdns.Server{PacketConn: pc, Handler: f.handler(true)}
	tcp := &mdns.Server{Listener: ln, Handler: f.handler(false)}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return f
}

func (f *fakeServer) set(name string, qt uint16, rrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zone[mdns.Fqdn(name)+" "+mdns.TypeToString[qt]] = rrs
}

func (f *fakeServer) setRcode(qt uint16, rc int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rcode[qt] = rc
}

func (f *fakeServer) setTruncate(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.truncate = v
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries
}

func (f *fakeServer) handler(udp bool) mdns.HandlerFunc {
	return func(w mdns.ResponseWriter, r *mdns.Msg) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queries++
		q := r.Question[0]
		m := new(mdns.Msg)
		m.SetReply(r)
		if rc, ok := f.rcode[q.Qtype]; ok {
			m.Rcode = rc
			w.WriteMsg(m)
			return
		}
		if udp && f.truncate {
			m.Truncated = true
			w.WriteMsg(m)
			return
		}
		rrs, ok := f.zone[strings.ToLower(q.Name)+" "+mdns.TypeToString[q.Qtype]]
		if !ok && !f.hasName(q.Name) {
			m.Rcode = mdns.RcodeNameError
		}
		for _, s := range rrs {
			rr, err := mdns.NewRR(s)
			if err != nil {
				panic(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	}
}

func (f *fakeServer) hasName(name string) bool {
	for k := range f.zone {
		if strings.HasPrefix(k, strings.ToLower(name)+" ") {
			return true
		}
	}
	return false
}

func decodeData(t *testing.T, raw json.RawMessage) Data {
	t.Helper()
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func populate(f *fakeServer) {
	f.set("example.com", mdns.TypeA, "example.com. 300 IN A 192.0.2.2", "example.com. 300 IN A 192.0.2.1", "example.com. 300 IN A 192.0.2.1")
	f.set("example.com", mdns.TypeAAAA, "example.com. 300 IN AAAA 2001:db8::1")
	f.set("example.com", mdns.TypeMX, "example.com. 3600 IN MX 10 MX1.Example.COM.", "example.com. 3600 IN MX 20 mx2.example.com.")
	f.set("example.com", mdns.TypeNS, "example.com. 86400 IN NS ns2.example.net.", "example.com. 86400 IN NS ns1.example.net.")
	f.set("example.com", mdns.TypeTXT, `example.com. 300 IN TXT "v=spf1 " "-all"`)
	f.set("example.com", mdns.TypeCAA, `example.com. 300 IN CAA 0 issue "letsencrypt.org"`)
	f.set("example.com", mdns.TypeSOA, "example.com. 3600 IN SOA ns1.example.net. hostmaster.example.com. 2026112301 7200 3600 1209600 300")
	f.set("www.example.com", mdns.TypeCNAME, "www.example.com. 300 IN CNAME example.com.")
	f.set("www.example.com", mdns.TypeA, "www.example.com. 300 IN CNAME example.com.", "example.com. 300 IN A 192.0.2.1")
}

func TestRun(t *testing.T) {
	f := newFakeServer(t)
	populate(f)
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	c := New(Config{Resolvers: []string{f.addr}, Timeout: time.Second, Now: func() time.Time { return at }})

	obs, err := c.Run(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if obs.Check != "dns" || !obs.ObservedAt.Equal(at) || len(obs.Hash) != 64 {
		t.Errorf("observation header: %+v", obs)
	}
	d := decodeData(t, obs.Data)
	want := map[string][]string{
		"A":     {"192.0.2.1", "192.0.2.2"},
		"AAAA":  {"2001:db8::1"},
		"CNAME": {},
		"MX":    {"10 mx1.example.com", "20 mx2.example.com"},
		"NS":    {"ns1.example.net", "ns2.example.net"},
		"TXT":   {"v=spf1 -all"},
		"CAA":   {`0 issue "letsencrypt.org"`},
		"SOA":   {"ns1.example.net hostmaster.example.com 2026112301 7200 3600 1209600 300"},
	}
	for typ, vals := range want {
		set, ok := d.Records[typ]
		if !ok {
			t.Errorf("%s missing", typ)
			continue
		}
		if set.Rcode != "NOERROR" || set.Error != "" {
			t.Errorf("%s: rcode=%q error=%q", typ, set.Rcode, set.Error)
		}
		var got []string
		for _, v := range set.Values {
			got = append(got, v.Value)
		}
		if strings.Join(got, "|") != strings.Join(vals, "|") {
			t.Errorf("%s = %q, want %q", typ, got, vals)
		}
	}
	if d.Records["MX"].Values[0].TTL != 3600 {
		t.Errorf("TTL not kept: %+v", d.Records["MX"])
	}

	// Same answers, same hash; the hash is over canonical data.
	again, _ := c.Run(t.Context(), "example.com")
	if again.Hash != obs.Hash {
		t.Error("hash differs for identical answers")
	}

	// A CNAME chain keeps only records of the asked type.
	www, err := c.Run(t.Context(), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	wd := decodeData(t, www.Data)
	if v := wd.Records["A"].Values; len(v) != 1 || v[0].Value != "192.0.2.1" {
		t.Errorf("www A = %+v", v)
	}
	if v := wd.Records["CNAME"].Values; len(v) != 1 || v[0].Value != "example.com" {
		t.Errorf("www CNAME = %+v", v)
	}
}

func TestNXDOMAIN(t *testing.T) {
	f := newFakeServer(t)
	c := New(Config{Resolvers: []string{f.addr}, Timeout: time.Second})
	obs, err := c.Run(t.Context(), "unregistered-example.com")
	if err != nil {
		t.Fatal(err)
	}
	d := decodeData(t, obs.Data)
	for typ, set := range d.Records {
		if set.Rcode != "NXDOMAIN" || len(set.Values) != 0 {
			t.Errorf("%s: %+v", typ, set)
		}
	}
}

func TestResolverFallback(t *testing.T) {
	bad := newFakeServer(t)
	bad.setRcode(mdns.TypeMX, mdns.RcodeServerFailure)
	bad.setRcode(mdns.TypeNS, mdns.RcodeRefused)
	populate(bad)
	good := newFakeServer(t)
	populate(good)

	c := New(Config{Resolvers: []string{bad.addr, good.addr}, Timeout: time.Second})
	obs, err := c.Run(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	d := decodeData(t, obs.Data)
	if len(d.Records["MX"].Values) != 2 || len(d.Records["NS"].Values) != 2 {
		t.Errorf("fallback not used: MX=%+v NS=%+v", d.Records["MX"], d.Records["NS"])
	}
	if n := good.count(); n != 2 {
		t.Errorf("second resolver got %d queries, want 2 (MX and NS)", n)
	}
}

func TestPartialAndTotalFailure(t *testing.T) {
	f := newFakeServer(t)
	populate(f)
	f.setRcode(mdns.TypeCAA, mdns.RcodeServerFailure)
	c := New(Config{Resolvers: []string{f.addr}, Timeout: time.Second})
	obs, err := c.Run(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("partial failure should still observe: %v", err)
	}
	if caa := decodeData(t, obs.Data).Records["CAA"]; caa.Error == "" || caa.Rcode != "" {
		t.Errorf("CAA = %+v, want error", caa)
	}

	// Nothing listens here: every query times out.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()
	c = New(Config{Resolvers: []string{dead}, Timeout: 100 * time.Millisecond})
	if _, err := c.Run(t.Context(), "example.com"); err == nil || !strings.Contains(err.Error(), "every query failed") {
		t.Errorf("err = %v", err)
	}
}

func TestTruncatedRetriesOverTCP(t *testing.T) {
	f := newFakeServer(t)
	populate(f)
	f.setTruncate(true)
	c := New(Config{Resolvers: []string{f.addr}, Timeout: time.Second})
	obs, err := c.Run(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a := decodeData(t, obs.Data).Records["A"].Values; len(a) != 2 {
		t.Errorf("A over TCP = %+v", a)
	}
}

func TestCancelledContext(t *testing.T) {
	f := newFakeServer(t)
	populate(f)
	c := New(Config{Resolvers: []string{f.addr}, Timeout: time.Second})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Run(ctx, "example.com"); err == nil {
		t.Error("want error for cancelled context")
	}
}
