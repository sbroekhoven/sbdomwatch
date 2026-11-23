package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunExitCodes(t *testing.T) {
	noEnv := filepath.Join(t.TempDir(), "none.env")
	badEnv := writeTemp(t, ".env", "NOT VALID\n")
	badCfg := writeTemp(t, "config.yaml", "token: abc\n")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"version"}, exitOK, "sbdomwatch dev (", ""},
		{"version json", []string{"version", "-o", "json"}, exitOK, `"version":"dev"`, ""},
		{"root help", []string{}, exitOK, "sbdomwatch serve", ""},
		{"bad output", []string{"version", "-o", "xml"}, exitUsage, "", "invalid --output"},
		{"unknown command", []string{"frobnicate"}, exitUsage, "", "unknown command"},
		{"unknown flag", []string{"version", "--nope"}, exitUsage, "", "unknown flag"},
		{"extra arg", []string{"version", "x"}, exitUsage, "", "unknown command"},
		{"bad env file", []string{"version", "--env-file", badEnv}, exitError, "", "line 1"},
		{"missing config", []string{"serve", "--config", filepath.Join(t.TempDir(), "nope.yaml")}, exitError, "", "read config"},
		{"secret in config", []string{"serve", "--config", badCfg}, exitError, "", "looks like a secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--env-file", noEnv}, tt.args...)
			code := run(t.Context(), args, &stdout, &stderr, lookupFrom(nil))
			if code != tt.wantCode {
				t.Errorf("code = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want containing %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want containing %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe for one writer and one reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestServe(t *testing.T) {
	const secret = "tok-from-dotenv-123"
	envFile := writeTemp(t, ".env", "SBDOMWATCH_TOKEN="+secret+"\n")
	cfg := writeTemp(t, "config.yaml", "listen: \"127.0.0.1:0\"\n")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout bytes.Buffer
	var stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--env-file", envFile, "serve", "--config", cfg}, &stdout, &stderr, lookupFrom(nil))
	}()

	addr := waitForListen(t, &stderr)
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("exit code = %d; stderr: %s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}

	logs := stderr.String()
	if strings.Contains(logs, secret) {
		t.Errorf("logs contain the token: %s", logs)
	}
	if !strings.Contains(logs, `"token_set":true`) {
		t.Errorf("token from .env not picked up: %s", logs)
	}
}

func waitForListen(t *testing.T, logs *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc := bufio.NewScanner(strings.NewReader(logs.String()))
		for sc.Scan() {
			var line struct {
				Msg  string `json:"msg"`
				Addr string `json:"addr"`
			}
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "api listening" {
				return line.Addr
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not log its address; logs: %s", logs.String())
	return ""
}
