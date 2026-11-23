package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

func sampleEvent() Event {
	return Event{
		ID: 42, WatchID: 7, Type: MXAppeared, Severity: High,
		OccurredAt: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
		Payload: Payload{
			Domain: "example.com", Template: "owned",
			Origins: []OriginRef{{Origin: "incident", Reason: "brand `abuse`\n@everyone", Reference: "INC-7"}},
			Change:  &diff.Change{Path: "dns.MX", Kind: diff.Added, Before: []string{}, After: []string{"10 mail.example.com"}, Added: []string{"10 mail.example.com"}, Removed: []string{}},
		},
	}
}

func TestWebhookDeliver(t *testing.T) {
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	w := NewWebhook(srv.URL+"/hook", "s3cret", Info, srv.Client(), "sbdomwatch/test")
	w.now = func() time.Time { return time.Unix(1700000000, 0) }
	if err := w.Deliver(t.Context(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get(HeaderEvent) != "mx_appeared" || got.Header.Get(HeaderDelivery) != "42" ||
		got.Header.Get("Content-Type") != "application/json" || got.Header.Get("User-Agent") != "sbdomwatch/test" {
		t.Errorf("headers = %v", got.Header)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("1700000000."))
	mac.Write(body)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); got.Header.Get(HeaderSignature) != want {
		t.Errorf("signature = %s, want %s", got.Header.Get(HeaderSignature), want)
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil || e.ID != 42 || e.Payload.Change.Path != "dns.MX" {
		t.Errorf("body = %s", body)
	}

	unsigned := NewWebhook(srv.URL, "", Info, srv.Client(), "x")
	if err := unsigned.Deliver(t.Context(), sampleEvent()); err != nil || got.Header.Get(HeaderSignature) != "" {
		t.Errorf("unsigned: err=%v signature=%q", err, got.Header.Get(HeaderSignature))
	}
}

func TestDiscordDeliver(t *testing.T) {
	var msg struct {
		Username        string `json:"username"`
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	d := NewDiscord(srv.URL, Medium, srv.Client(), "x")
	if err := d.Deliver(t.Context(), sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("mentions not disabled: %s", raw)
	}
	for _, want := range []string{"**HIGH · mx_appeared**", "`example.com` (owned)", "dns.MX added: `10 mail.example.com`", "INC-7"} {
		if !strings.Contains(msg.Content, want) {
			t.Errorf("content %q lacks %q", msg.Content, want)
		}
	}
	if strings.Contains(msg.Content, "`abuse`") || strings.Contains(msg.Content, "\n@everyone") {
		t.Errorf("untrusted text not neutralized: %q", msg.Content)
	}
}

func TestDiscordTextLimits(t *testing.T) {
	e := sampleEvent()
	for range 500 {
		e.Payload.Origins = append(e.Payload.Origins, OriginRef{Origin: "intel", Reason: strings.Repeat("x", 100)})
	}
	if n := len(DiscordText(e)); n > maxDiscordLen+3 {
		t.Errorf("text length %d", n)
	}
	b := Event{Type: BaselineComplete, Severity: Info, Payload: Payload{Domain: "a.com", Inventory: map[string][]string{"dns.A": {}}, VolatileFields: []string{"dns.A"}, Observations: 3}}
	if got := DiscordText(b); !strings.Contains(got, "Baseline of 3 observation(s), 1 fields, volatile: `dns.A`") {
		t.Errorf("baseline text = %q", got)
	}
}

func TestPostErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/429":
			w.Header().Set("Retry-After", "2.5")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/404":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	err := post(t.Context(), srv.Client(), srv.URL+"/429", "x", nil, nil)
	var ra *RetryAfterError
	if !errors.As(err, &ra) || ra.After != 2500*time.Millisecond {
		t.Errorf("429: %v", err)
	}
	if err := post(t.Context(), srv.Client(), srv.URL+"/404", "x", nil, nil); err == nil || err.Error() != "HTTP 404" {
		t.Errorf("404: %v", err)
	}

	// A network failure must not leak the secret part of the URL.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	secretURL := "http://" + addr + "/api/webhooks/123/SUPERSECRETTOKEN"
	err = post(t.Context(), http.DefaultClient, secretURL, "x", nil, nil)
	if err == nil || strings.Contains(err.Error(), "SUPERSECRETTOKEN") || strings.Contains(err.Error(), "/api/webhooks") {
		t.Errorf("error leaks URL: %v", err)
	}
	if err := post(t.Context(), http.DefaultClient, "::bad url SUPERSECRETTOKEN", "x", nil, nil); err == nil || strings.Contains(err.Error(), "SUPERSECRET") {
		t.Errorf("bad URL error leaks: %v", err)
	}
}

func TestRouter(t *testing.T) {
	route := Router([]Sink{NewDiscord("u", Medium, nil, ""), NewWebhook("u", "", Info, nil, "")})
	if got := route(Event{Severity: Info}); len(got) != 1 || got[0] != "webhook" {
		t.Errorf("info -> %v", got)
	}
	if got := route(Event{Severity: High}); len(got) != 2 {
		t.Errorf("high -> %v", got)
	}
}
