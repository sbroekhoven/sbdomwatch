package client

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

const token = "client-test-token-0123456789abcdef01"

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "c.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := watch.Defaults{
		Intervals:    map[watch.Template]time.Duration{watch.TemplateOwned: time.Hour, watch.TemplateCandidate: 6 * time.Hour, watch.TemplateThirdParty: 6 * time.Hour},
		CandidateTTL: 90 * 24 * time.Hour,
	}
	srv := httptest.NewServer(api.New(":0", api.Deps{Store: st, Token: token, Defaults: d, Log: slog.New(slog.DiscardHandler)}).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestNew(t *testing.T) {
	for _, u := range []string{"", "localhost:8480", "ftp://x", "http://"} {
		if _, err := New(u, token, "", nil); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	srv := newServer(t)
	c, err := New(srv.URL+"/", token, "seb", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	res, err := c.AddWatch(ctx, watch.AddRequest{Domain: "Degiro.NL.", Template: watch.TemplateOwned, Reason: "company"})
	if err != nil || !res.Created || res.Watch.Domain != "degiro.nl" || res.Watch.Origins[0].AddedBy != "seb" {
		t.Fatalf("add: %+v, %v", res, err)
	}
	bulk, err := c.BulkAdd(ctx, []watch.AddRequest{
		{Domain: "degiro.nl", Template: watch.TemplateOwned, Reason: "second"},
		{Domain: "bücher.de", Template: watch.TemplateCandidate, Reason: "idn", Tags: map[string]string{"p": "x"}},
	})
	if err != nil || bulk.Created != 1 || bulk.Merged != 1 {
		t.Fatalf("bulk: %+v, %v", bulk, err)
	}
	ws, err := c.ListWatches(ctx, ListOptions{Tag: "p=x"})
	if err != nil || len(ws) != 1 || ws[0].Domain != "xn--bcher-kva.de" {
		t.Fatalf("list: %+v, %v", ws, err)
	}
	w, err := c.GetWatch(ctx, "bücher.de")
	if err != nil || w.Domain != "xn--bcher-kva.de" {
		t.Fatalf("get unicode: %+v, %v", w, err)
	}
	yes := true
	if w, err = c.PatchWatch(ctx, "degiro.nl", watch.PatchRequest{Paused: &yes}); err != nil || w.State != watch.StatePaused {
		t.Fatalf("pause: %+v, %v", w, err)
	}
	if w, err = c.ArchiveWatch(ctx, "degiro.nl"); err != nil || w.State != watch.StateArchived {
		t.Fatalf("archive: %+v, %v", w, err)
	}

	_, err = c.GetWatch(ctx, "nope.com")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing: %v", err)
	}
	_, err = c.AddWatch(ctx, watch.AddRequest{Domain: "a.com", Template: watch.TemplateOwned})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadRequest || len(ae.Detail.Fields) != 1 || ae.Detail.Fields[0].Field != "reason" {
		t.Errorf("empty reason: %v", err)
	}

	bad, _ := New(srv.URL, "wrong", "", nil)
	if _, err := bad.ListWatches(ctx, ListOptions{}); !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Errorf("wrong token: %v", err)
	}
}
