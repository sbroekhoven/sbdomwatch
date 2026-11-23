package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		file    string // empty: no file
		env     map[string]string
		wantErr string
		check   func(t *testing.T, c Server)
	}{
		{
			name: "defaults without file",
			check: func(t *testing.T, c Server) {
				if c.Listen != ":8480" || c.Defaults.BaselineGap != 3*time.Minute {
					t.Errorf("unexpected defaults: %+v", c)
				}
			},
		},
		{
			name: "file overrides defaults",
			file: "listen: \"127.0.0.1:9000\"\ndefaults:\n  baseline_gap: 5m\n  intervals:\n    owned: 30m\n",
			check: func(t *testing.T, c Server) {
				if c.Listen != "127.0.0.1:9000" {
					t.Errorf("listen = %q", c.Listen)
				}
				if c.Defaults.BaselineGap != 5*time.Minute || c.Defaults.Intervals.Owned != 30*time.Minute {
					t.Errorf("durations not decoded: %+v", c.Defaults)
				}
				if c.Defaults.Intervals.Candidate != 6*time.Hour {
					t.Errorf("unset field lost its default: %v", c.Defaults.Intervals.Candidate)
				}
			},
		},
		{
			name: "env overrides file and supplies secrets",
			file: "listen: \":9000\"\nsinks:\n  discord:\n    webhook_env: MY_HOOK\n",
			env:  map[string]string{EnvListen: ":9100", EnvToken: "t0ken", "MY_HOOK": "https://hook"},
			check: func(t *testing.T, c Server) {
				if c.Listen != ":9100" || c.Token != "t0ken" || c.DiscordWebhook != "https://hook" {
					t.Errorf("env not applied: listen=%q token_set=%v hook_set=%v", c.Listen, c.Token != "", c.DiscordWebhook != "")
				}
			},
		},
		{name: "empty file", file: "", check: func(t *testing.T, c Server) {}},
		{name: "unknown key", file: "lisen: \":1\"\n", wantErr: "lisen"},
		{name: "token in file", file: "token: abc\n", wantErr: "token looks like a secret"},
		{name: "nested secret in file", file: "sinks:\n  discord:\n    webhook: https://x\n", wantErr: "sinks.discord.webhook looks like a secret"},
		{name: "bad listen", file: "listen: nope\n", wantErr: "listen"},
		{name: "bad resolver", file: "resolvers: [\"1.1.1.1\"]\n", wantErr: "resolver"},
		{name: "bad level", env: map[string]string{EnvLogLevel: "loud"}, wantErr: "log_level"},
		{name: "zero rate limit", file: "rate_limits:\n  dns_per_sec: 0\n", wantErr: "dns_per_sec"},
		{name: "short interval", file: "defaults:\n  intervals:\n    owned: 10s\n", wantErr: "intervals.owned"},
		{name: "bad duration", file: "defaults:\n  baseline_gap: soon\n", wantErr: "decode"},
		{name: "bad webhook env name", file: "sinks:\n  discord:\n    webhook_env: \"not valid\"\n", wantErr: "webhook_env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := ""
			if tt.file != "" || tt.name == "empty file" {
				path = writeFile(t, tt.file)
			}
			c, err := Load(path, envMap(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), envMap(nil))
	if err == nil {
		t.Fatal("want error for missing explicit config file")
	}
}

func TestLogValueHidesSecrets(t *testing.T) {
	c := Default()
	c.Token = "super-secret-token"
	c.DiscordWebhook = "https://discord.example/hook/secret"
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "config", c)
	out := buf.String()
	for _, secret := range []string{c.Token, c.DiscordWebhook} {
		if strings.Contains(out, secret) {
			t.Errorf("log output contains secret: %s", out)
		}
	}
	if !strings.Contains(out, `"token_set":true`) {
		t.Errorf("want token_set in log output: %s", out)
	}
}
