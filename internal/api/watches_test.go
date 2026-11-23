package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

const testToken = "test-token-0123456789abcdef0123456789"

var testDefaults = watch.Defaults{
	Intervals: map[watch.Template]time.Duration{
		watch.TemplateOwned:      time.Hour,
		watch.TemplateCandidate:  6 * time.Hour,
		watch.TemplateThirdParty: 6 * time.Hour,
	},
	CandidateTTL: 90 * 24 * time.Hour,
}

type testAPI struct {
	t    *testing.T
	h    http.Handler
	st   *store.Store
	logs *bytes.Buffer
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "api.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	s := New(":0", Deps{Store: st, Token: testToken, Defaults: testDefaults, Log: log})
	return &testAPI{t: t, h: s.Handler(), st: st, logs: logs}
}

func (a *testAPI) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	a.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestAuth(t *testing.T) {
	a := newTestAPI(t)
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"token prefix", "Bearer " + testToken[:10], http.StatusUnauthorized},
		{"basic scheme", "Basic " + testToken, http.StatusUnauthorized},
		{"right token", "Bearer " + testToken, http.StatusOK},
		{"lowercase scheme", "bearer " + testToken, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := a.do(http.MethodGet, "/v1/watches", "", "Authorization", tt.header)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("missing WWW-Authenticate")
			}
		})
	}
	if strings.Contains(a.logs.String(), testToken) {
		t.Error("token appears in logs")
	}
	// healthz needs no token.
	rec := a.do(http.MethodGet, "/healthz", "", "Authorization", "")
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d", rec.Code)
	}
}

func TestEmptyTokenRejectsEverything(t *testing.T) {
	s := New(":0", Deps{Store: nil, Token: "", Log: slog.New(slog.DiscardHandler)})
	req := httptest.NewRequest(http.MethodGet, "/v1/watches", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

// TestPhase2Acceptance covers the phase 2 acceptance criteria through the API:
// adding the same domain twice merges origins, an empty reason is rejected,
// and Degiro.NL. and an IDN are stored normalized.
func TestPhase2Acceptance(t *testing.T) {
	a := newTestAPI(t)

	rec := a.do(http.MethodPost, "/v1/watches", `{"domain":"Degiro.NL.","template":"owned","reason":"company domain"}`, HeaderActor, "seb")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first add: %d %s", rec.Code, rec.Body)
	}
	if got := decode[store.AddResult](t, rec); got.Watch.Domain != "degiro.nl" || got.Watch.Origins[0].AddedBy != "seb" {
		t.Fatalf("first add stored %+v", got.Watch)
	}

	rec = a.do(http.MethodPost, "/v1/watches", `{"domain":"degiro.nl","template":"owned","reason":"brand abuse case","origin":"incident","reference":"INC-7"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("second add: %d %s", rec.Code, rec.Body)
	}
	merged := decode[store.AddResult](t, rec)
	if merged.Created || len(merged.Watch.Origins) != 2 || merged.Watch.Origins[1].AddedBy != "api" {
		t.Fatalf("merge result %+v", merged)
	}

	for _, body := range []string{
		`{"domain":"example.com","template":"owned","reason":""}`,
		`{"domain":"example.com","template":"owned","reason":"   "}`,
		`{"domain":"example.com","template":"owned"}`,
	} {
		rec = a.do(http.MethodPost, "/v1/watches", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("empty reason %s: status %d", body, rec.Code)
		}
		e := decode[ErrorBody](t, rec)
		if e.Error.Code != CodeInvalidArgument || len(e.Error.Fields) != 1 || e.Error.Fields[0].Field != "reason" {
			t.Errorf("error body = %+v", e)
		}
	}

	rec = a.do(http.MethodPost, "/v1/watches", `{"domain":"bücher.de","template":"candidate","reason":"idn"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("idn add: %d %s", rec.Code, rec.Body)
	}
	// The Unicode form in the path finds the punycode watch.
	rec = a.do(http.MethodGet, "/v1/watches/b%C3%BCcher.de", "")
	if rec.Code != http.StatusOK || decode[watch.Watch](t, rec).Domain != "xn--bcher-kva.de" {
		t.Fatalf("get idn: %d %s", rec.Code, rec.Body)
	}

	list := decode[ListResponse](t, a.do(http.MethodGet, "/v1/watches", ""))
	if len(list.Watches) != 2 {
		t.Fatalf("want 2 watches, got %d", len(list.Watches))
	}
}

func TestAddValidation(t *testing.T) {
	a := newTestAPI(t)
	tests := []struct {
		name, body string
		want       int
		wantField  string
	}{
		{"ip literal", `{"domain":"10.0.0.1","template":"owned","reason":"x"}`, 400, "domain"},
		{"single label", `{"domain":"intranet","template":"owned","reason":"x"}`, 400, "domain"},
		{"private tld", `{"domain":"nas.lan","template":"owned","reason":"x"}`, 400, "domain"},
		{"bad template", `{"domain":"a.com","template":"x","reason":"x"}`, 400, "template"},
		{"unknown field", `{"domain":"a.com","template":"owned","reason":"x","evil":1}`, 400, ""},
		{"not json", `domain=a.com`, 400, ""},
		{"trailing data", `{"domain":"a.com","template":"owned","reason":"x"} {}`, 400, ""},
		{"too large", `{"domain":"a.com","template":"owned","reason":"` + strings.Repeat("x", maxBodyBytes) + `"}`, 413, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := a.do(http.MethodPost, "/v1/watches", tt.body)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			e := decode[ErrorBody](t, rec)
			if tt.wantField != "" && (len(e.Error.Fields) == 0 || e.Error.Fields[0].Field != tt.wantField) {
				t.Errorf("fields = %+v, want %s", e.Error.Fields, tt.wantField)
			}
		})
	}
	rec := a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x"}`, HeaderActor, "bad actor!")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad actor: status %d", rec.Code)
	}
}

func TestBulk(t *testing.T) {
	a := newTestAPI(t)
	a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x"}`)

	rec := a.do(http.MethodPost, "/v1/watches:bulk", `{"watches":[
		{"domain":"a.com","template":"owned","reason":"x"},
		{"domain":"B.com.","template":"owned","reason":"y"},
		{"domain":"a.com","template":"owned","reason":"new reason"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", rec.Code, rec.Body)
	}
	got := decode[BulkResponse](t, rec)
	if got.Created != 1 || got.Merged != 1 || got.Unchanged != 1 {
		t.Errorf("summary = %+v", got)
	}

	rec = a.do(http.MethodPost, "/v1/watches:bulk", `{"watches":[
		{"domain":"c.com","template":"owned","reason":"x"},
		{"domain":"1.2.3.4","template":"owned","reason":""}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid bulk: %d", rec.Code)
	}
	e := decode[ErrorBody](t, rec)
	if len(e.Error.Fields) != 2 || e.Error.Fields[0].Field != "watches[1].domain" || e.Error.Fields[1].Field != "watches[1].reason" {
		t.Errorf("fields = %+v", e.Error.Fields)
	}
	if rec := a.do(http.MethodGet, "/v1/watches/c.com", ""); rec.Code != http.StatusNotFound {
		t.Errorf("invalid bulk stored c.com: %d", rec.Code)
	}

	var items []string
	for i := range MaxBulkItems + 1 {
		items = append(items, fmt.Sprintf(`{"domain":"d%d.com","template":"candidate","reason":"x"}`, i))
	}
	rec = a.do(http.MethodPost, "/v1/watches:bulk", `{"watches":[`+strings.Join(items, ",")+`]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized bulk: %d", rec.Code)
	}
	if rec := a.do(http.MethodPost, "/v1/watches:bulk", `{"watches":[]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty bulk: %d", rec.Code)
	}
}

func TestListFilters(t *testing.T) {
	a := newTestAPI(t)
	a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x","tags":{"profile":"degiro"}}`)
	a.do(http.MethodPost, "/v1/watches", `{"domain":"b.com","template":"candidate","reason":"x","origin":"typosquat"}`)
	a.do(http.MethodDelete, "/v1/watches/b.com", "")

	tests := []struct {
		query string
		want  int
		count int
	}{
		{"", 200, 1},
		{"?all=true", 200, 2},
		{"?state=archived", 200, 1},
		{"?tag=profile=degiro", 200, 1},
		{"?origin=typosquat&all=1", 200, 1},
		{"?state=bogus", 400, 0},
		{"?origin=bogus", 400, 0},
		{"?tag=novalue", 400, 0},
		{"?all=maybe", 400, 0},
		{"?stale=true", 200, 0},
		{"?stale=perhaps", 400, 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			rec := a.do(http.MethodGet, "/v1/watches"+tt.query, "")
			if rec.Code != tt.want {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}
			if tt.want == 200 {
				if n := len(decode[ListResponse](t, rec).Watches); n != tt.count {
					t.Errorf("count = %d, want %d", n, tt.count)
				}
			}
		})
	}
	// An empty list is [] not null.
	a2 := newTestAPI(t)
	if body := a2.do(http.MethodGet, "/v1/watches", "").Body.String(); !strings.Contains(body, `"watches":[]`) {
		t.Errorf("empty list body = %s", body)
	}
}

func TestPatchArchiveDelete(t *testing.T) {
	a := newTestAPI(t)
	a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x","tags":{"k":"v"}}`)

	tests := []struct {
		name, method, path, body string
		want                     int
		wantState                watch.State
	}{
		{"pause", http.MethodPatch, "/v1/watches/a.com", `{"paused":true}`, 200, watch.StatePaused},
		{"interval and tags", http.MethodPatch, "/v1/watches/A.COM.", `{"interval_sec":900,"tags":{"k":null,"n":"1"}}`, 200, watch.StatePaused},
		{"resume", http.MethodPatch, "/v1/watches/a.com", `{"paused":false}`, 200, watch.StateNew},
		{"bad interval", http.MethodPatch, "/v1/watches/a.com", `{"interval_sec":1}`, 400, ""},
		{"unknown field", http.MethodPatch, "/v1/watches/a.com", `{"state":"active"}`, 400, ""},
		{"missing", http.MethodPatch, "/v1/watches/nope.com", `{"paused":true}`, 404, ""},
		{"bad domain", http.MethodGet, "/v1/watches/localhost", "", 400, ""},
		{"archive", http.MethodDelete, "/v1/watches/a.com", "", 200, watch.StateArchived},
		{"patch archived", http.MethodPatch, "/v1/watches/a.com", `{"paused":true}`, 409, ""},
		{"archive again", http.MethodDelete, "/v1/watches/a.com", "", 200, watch.StateArchived},
		{"bad hard", http.MethodDelete, "/v1/watches/a.com?hard=perhaps", "", 400, ""},
		{"hard delete", http.MethodDelete, "/v1/watches/a.com?hard=true", "", 204, ""},
		{"gone", http.MethodGet, "/v1/watches/a.com", "", 404, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := a.do(tt.method, tt.path, tt.body)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if tt.wantState != "" {
				if got := decode[watch.Watch](t, rec); got.State != tt.wantState {
					t.Errorf("state = %s, want %s", got.State, tt.wantState)
				}
			}
		})
	}
	w, _ := a.st.ListWatches(t.Context(), store.Filter{All: true})
	if len(w) != 0 {
		t.Errorf("watches left after hard delete: %d", len(w))
	}
}

func TestHistory(t *testing.T) {
	a := newTestAPI(t)
	res := decode[store.AddResult](t, a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x"}`))
	now := time.Now().UTC().Truncate(time.Second)
	for i, at := range []time.Time{now.Add(-48 * time.Hour), now.Add(-time.Hour)} {
		o, err := check.NewObservation("dns", at, map[string]int{"n": i})
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.st.ApplyCheck(t.Context(), res.Watch.ID, func(w watch.Watch, st diff.State) (store.CheckResult, error) {
			return store.CheckResult{Watch: w, Diff: st, Observations: []check.Observation{o}, Next: now}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		query string
		want  int
		count int
	}{
		{"", 200, 2},
		{"?since=24h", 200, 1},
		{"?since=3d", 200, 2},
		{"?since=" + now.Add(-2*time.Hour).Format(time.RFC3339), 200, 1},
		{"?limit=1", 200, 1},
		{"?since=yesterday", 400, 0},
		{"?since=-5h", 400, 0},
		{"?limit=0", 400, 0},
		{"?limit=5000", 400, 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			rec := a.do(http.MethodGet, "/v1/watches/A.com./history"+tt.query, "")
			if rec.Code != tt.want {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}
			if tt.want != 200 {
				return
			}
			h := decode[HistoryResponse](t, rec)
			if h.Domain != "a.com" || len(h.Entries) != tt.count {
				t.Errorf("got %s with %d entries, want %d", h.Domain, len(h.Entries), tt.count)
			}
			if len(h.Entries) > 0 && string(h.Entries[0].Data) != `{"n":1}` {
				t.Errorf("newest entry data = %s", h.Entries[0].Data)
			}
		})
	}
	if rec := a.do(http.MethodGet, "/v1/watches/nope.com/history", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing watch: %d", rec.Code)
	}
}

func TestEvents(t *testing.T) {
	a := newTestAPI(t)
	now := time.Now().UTC().Truncate(time.Second)
	for _, d := range []string{"a.com", "b.com"} {
		a.do(http.MethodPost, "/v1/watches", `{"domain":"`+d+`","template":"owned","reason":"x"}`)
	}
	emit := func(domain string, e events.Event) {
		w, _ := a.st.GetWatch(t.Context(), domain)
		_, err := a.st.ApplyCheck(t.Context(), w.ID, func(w watch.Watch, st diff.State) (store.CheckResult, error) {
			e.Payload.Domain = w.Domain
			return store.CheckResult{Watch: w, Diff: st, Events: []events.Event{e}, Next: now}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	emit("a.com", events.Event{Type: events.BaselineComplete, Severity: events.Info, OccurredAt: now.Add(-48 * time.Hour)})
	emit("a.com", events.Event{Type: events.MXAppeared, Severity: events.High, OccurredAt: now.Add(-time.Hour)})
	emit("b.com", events.Event{Type: events.NSChanged, Severity: events.Critical, OccurredAt: now.Add(-2 * time.Hour)})

	tests := []struct {
		query string
		want  int
		types []events.Type
	}{
		{"", 200, []events.Type{events.MXAppeared, events.NSChanged, events.BaselineComplete}},
		{"?since=24h", 200, []events.Type{events.MXAppeared, events.NSChanged}},
		{"?type=ns_changed,mx_appeared", 200, []events.Type{events.MXAppeared, events.NSChanged}},
		{"?watch=A.COM.", 200, []events.Type{events.MXAppeared, events.BaselineComplete}},
		{"?severity=critical", 200, []events.Type{events.NSChanged}},
		{"?limit=1", 200, []events.Type{events.MXAppeared}},
		{"?type=bogus", 400, nil},
		{"?severity=loud", 400, nil},
		{"?watch=localhost", 400, nil},
		{"?since=soon", 400, nil},
		{"?limit=0", 400, nil},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			rec := a.do(http.MethodGet, "/v1/events"+tt.query, "")
			if rec.Code != tt.want {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body)
			}
			if tt.want != 200 {
				return
			}
			got := decode[EventsResponse](t, rec).Events
			if len(got) != len(tt.types) {
				t.Fatalf("got %d events, want %v", len(got), tt.types)
			}
			for i := range got {
				if got[i].Type != tt.types[i] || got[i].ID == 0 || got[i].Payload.Domain == "" {
					t.Errorf("event %d = %+v", i, got[i])
				}
			}
		})
	}
	if rec := a.do(http.MethodGet, "/v1/events", "", "Authorization", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("events without token: %d", rec.Code)
	}
}

func TestActions(t *testing.T) {
	a := newTestAPI(t)
	a.do(http.MethodPost, "/v1/watches", `{"domain":"a.com","template":"owned","reason":"x"}`)
	tests := []struct {
		name, path, body string
		want             int
	}{
		{"confirm before baseline", "/v1/watches/a.com:confirm", "", 409},
		{"rebaseline before baseline", "/v1/watches/a.com:rebaseline", "", 409},
		{"relearn is allowed any time", "/v1/watches/A.COM.:rebaseline", `{"relearn":true}`, 200},
		{"unknown verb", "/v1/watches/a.com:explode", "", 404},
		{"no verb", "/v1/watches/a.com", "", 405},
		{"bad domain", "/v1/watches/localhost:confirm", "", 400},
		{"missing watch", "/v1/watches/nope.com:confirm", "", 404},
		{"bad body", "/v1/watches/a.com:rebaseline", `{"relearn":"yes"}`, 400},
		{"unknown field", "/v1/watches/a.com:rebaseline", `{"force":true}`, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := a.do(http.MethodPost, tt.path, tt.body); rec.Code != tt.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
		})
	}
	log, _ := a.st.AuditLog(t.Context(), 1)
	if len(log) != 1 || log[0].Action != "watch.relearn" {
		t.Errorf("audit = %+v", log)
	}
}
