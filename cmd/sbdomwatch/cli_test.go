package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	rdapcheck "github.com/sbroekhoven/sbdomwatch/internal/check/rdap"
	"github.com/sbroekhoven/sbdomwatch/internal/config"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

const cliToken = "cli-test-token-0123456789abcdef0123"

type cliEnv struct {
	t   *testing.T
	env map[string]string
	st  *store.Store
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "cli.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	srv := httptest.NewServer(api.New(":0", api.Deps{
		Store: st, Token: cliToken, Defaults: cfg.WatchDefaults(), Log: slog.New(slog.DiscardHandler),
		Extractors: map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts, rdapcheck.Name: rdapcheck.Facts},
	}).Handler())
	t.Cleanup(srv.Close)
	return &cliEnv{t: t, st: st, env: map[string]string{
		config.EnvURL:   srv.URL,
		config.EnvToken: cliToken,
		"USER":          "seb",
		"HOME":          t.TempDir(),
	}}
}

func (e *cliEnv) run(args ...string) (code int, stdout, stderr string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	all := append([]string{"--env-file", filepath.Join(e.t.TempDir(), "none")}, args...)
	code = run(e.t.Context(), all, &out, &errb, lookupFrom(e.env))
	return code, out.String(), errb.String()
}

// TestPhase2AcceptanceCLI: adding the same domain twice merges origins, an
// empty reason is rejected, and Degiro.NL. and an IDN are stored normalized.
func TestPhase2AcceptanceCLI(t *testing.T) {
	e := newCLIEnv(t)
	steps := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{[]string{"add", "Degiro.NL.", "--template", "owned", "--reason", "company domain"}, 0, "added degiro.nl (owned, new, 1 origin(s))", ""},
		{[]string{"add", "degiro.nl", "--template", "owned", "--reason", "incident 7", "--origin", "incident", "--reference", "INC-7"}, 0, "merged degiro.nl (owned, new, 2 origin(s))", ""},
		{[]string{"add", "DEGIRO.NL", "--template", "owned", "--reason", "company domain"}, 0, "unchanged degiro.nl", ""},
		{[]string{"add", "example.com", "--template", "owned", "--reason", ""}, exitUsage, "", "--reason is required"},
		{[]string{"add", "example.com", "--template", "owned", "--reason", "   "}, exitUsage, "", "--reason is required"},
		{[]string{"add", "example.com", "--template", "owned"}, exitUsage, "", "--reason is required"},
		{[]string{"add", "bücher.de", "--template", "candidate", "--reason", "idn", "--tag", "profile=books"}, 0, "added xn--bcher-kva.de (bücher.de)", ""},
		{[]string{"show", "degiro.nl"}, 0, "INC-7", ""},
	}
	for _, s := range steps {
		code, out, errOut := e.run(s.args...)
		if code != s.wantCode || !strings.Contains(out, s.wantStdout) || !strings.Contains(errOut, s.wantStderr) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", s.args, code, out, errOut)
		}
	}
	ws, err := e.st.ListWatches(t.Context(), store.Filter{All: true})
	if err != nil || len(ws) != 2 || ws[0].Domain != "degiro.nl" || ws[1].Domain != "xn--bcher-kva.de" {
		t.Fatalf("stored: %+v, %v", ws, err)
	}
	if len(ws[0].Origins) != 2 || ws[0].Origins[0].AddedBy != "seb" {
		t.Errorf("origins: %+v", ws[0].Origins)
	}
}

func TestCLICommands(t *testing.T) {
	e := newCLIEnv(t)
	good := filepath.Join(t.TempDir(), "owned.txt")
	writeFile(t, good, "# owned domains\nexample.com\n\nExample.COM.  # duplicate\nexample.org\n")
	bad := filepath.Join(t.TempDir(), "bad.txt")
	writeFile(t, bad, "example.net\n10.0.0.1\nlocalhost\n")

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"import", []string{"import", good, "--template", "owned", "--reason", "company domain"}, 0, "imported 2 domain(s): 2 added, 0 merged, 0 unchanged", ""},
		{"import invalid", []string{"import", bad, "--template", "owned", "--reason", "x"}, exitUsage, "", "line 2"},
		{"import missing file", []string{"import", "/nonexistent/file", "--template", "owned", "--reason", "x"}, exitError, "", "open"},
		{"import no reason", []string{"import", good, "--template", "owned"}, exitUsage, "", "--reason"},
		{"ls", []string{"ls"}, 0, "example.com", ""},
		{"ls tag none", []string{"ls", "--tag", "profile=x"}, 0, "DOMAIN", ""},
		{"ls bad state", []string{"ls", "--state", "bogus"}, exitUsage, "", "unknown state"},
		{"pause", []string{"pause", "example.com"}, 0, "example.com: paused", ""},
		{"ls paused", []string{"ls", "--state", "paused"}, 0, "example.com", ""},
		{"resume", []string{"resume", "example.com"}, 0, "example.com: new", ""},
		{"archive", []string{"archive", "example.org"}, 0, "example.org: archived", ""},
		{"pause archived", []string{"pause", "example.org"}, exitError, "", "archived"},
		{"show missing", []string{"show", "nope.com"}, exitNotFound, "", "not found"},
		{"pause missing", []string{"pause", "nope.com"}, exitNotFound, "", ""},
		{"show invalid", []string{"show", "localhost"}, exitUsage, "", "single-label"},
		{"add bad tag", []string{"add", "a.com", "--template", "owned", "--reason", "x", "--tag", "novalue"}, exitUsage, "", "key=value"},
		{"add bad interval", []string{"add", "a.com", "--template", "owned", "--reason", "x", "--interval", "1s"}, exitUsage, "", "interval_sec"},
		{"add ip", []string{"add", "1.2.3.4", "--template", "owned", "--reason", "x"}, exitUsage, "", "IP"},
		{"add no args", []string{"add"}, exitUsage, "", "accepts 1 arg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := e.run(tt.args...)
			if code != tt.wantCode {
				t.Errorf("code = %d, want %d; stdout=%q stderr=%q", code, tt.wantCode, out, errOut)
			}
			if !strings.Contains(out, tt.wantStdout) || !strings.Contains(errOut, tt.wantStderr) {
				t.Errorf("stdout=%q (want %q) stderr=%q (want %q)", out, tt.wantStdout, errOut, tt.wantStderr)
			}
		})
	}
	if ws, _ := e.st.ListWatches(t.Context(), store.Filter{Domains: []string{"example.net"}, All: true}); len(ws) != 0 {
		t.Error("invalid import stored example.net")
	}

	code, out, _ := e.run("ls", "--all", "-o", "json")
	var ws []watch.Watch
	if code != 0 || json.Unmarshal([]byte(out), &ws) != nil || len(ws) != 2 {
		t.Errorf("ls json: code=%d out=%s", code, out)
	}
}

func TestCLINeedsToken(t *testing.T) {
	e := newCLIEnv(t)
	delete(e.env, config.EnvToken)
	code, _, errOut := e.run("ls")
	if code != exitError || !strings.Contains(errOut, "SBDOMWATCH_TOKEN is not set") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	e.env[config.EnvToken] = "wrong"
	code, _, errOut = e.run("ls")
	if code != exitError || !strings.Contains(errOut, "HTTP 401") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := writeTempAt(path, content); err != nil {
		t.Fatal(err)
	}
}
