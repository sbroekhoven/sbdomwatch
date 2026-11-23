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

const testToken = "0123456789abcdef0123456789abcdef"

// envMap returns a lookup over m that supplies a valid token unless m sets one.
func envMap(m map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		if k == EnvToken {
			return testToken
		}
		return ""
	}
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
			env:  map[string]string{EnvListen: ":9100", EnvToken: testToken + "x", "MY_HOOK": "https://discord.com/api/webhooks/1/x"},
			check: func(t *testing.T, c Server) {
				if c.Listen != ":9100" || c.Token != testToken+"x" || c.DiscordWebhook != "https://discord.com/api/webhooks/1/x" {
					t.Errorf("env not applied: listen=%q token_set=%v hook_set=%v", c.Listen, c.Token != "", c.DiscordWebhook != "")
				}
			},
		},
		{name: "empty file", file: "", check: func(t *testing.T, c Server) {}},
		{name: "missing token", env: map[string]string{EnvToken: ""}, wantErr: "SBDOMWATCH_TOKEN must be set"},
		{name: "short token", env: map[string]string{EnvToken: "short"}, wantErr: "at least 32"},
		{name: "short candidate ttl", file: "defaults:\n  candidate_ttl: 1h\n", wantErr: "candidate_ttl"},
		{name: "negative expiry warning", file: "defaults:\n  expiry_warning: -1h\n", wantErr: "expiry_warning"},
		{name: "bad workers", file: "scheduler:\n  workers: 0\n", wantErr: "scheduler.workers"},
		{name: "bad tick", file: "scheduler:\n  tick: 10ms\n", wantErr: "scheduler.tick"},
		{name: "discord url", env: map[string]string{"SBDOMWATCH_DISCORD_WEBHOOK": "https://discord.com/api/webhooks/1/abc"}, check: func(t *testing.T, c Server) {
			if c.DiscordWebhook == "" || c.Sinks.Discord.MinSeverity != "medium" {
				t.Errorf("discord: %+v", c.Sinks)
			}
		}},
		{name: "bad discord url", env: map[string]string{"SBDOMWATCH_DISCORD_WEBHOOK": "https://evil.example/api/webhooks/SECRETPART"}, wantErr: "SBDOMWATCH_DISCORD_WEBHOOK is not a Discord webhook URL"},
		{name: "http discord url", env: map[string]string{"SBDOMWATCH_DISCORD_WEBHOOK": "http://discord.com/api/webhooks/1/SECRETPART"}, wantErr: "not a Discord webhook"},
		{name: "webhook url and secret", env: map[string]string{"SBDOMWATCH_WEBHOOK_URL": "http://sbalert:8080/in", "SBDOMWATCH_WEBHOOK_SECRET": "k"}, check: func(t *testing.T, c Server) {
			if c.WebhookURL == "" || c.WebhookSecret != "k" {
				t.Errorf("webhook not loaded")
			}
		}},
		{name: "bad webhook url", env: map[string]string{"SBDOMWATCH_WEBHOOK_URL": "ftp://x/SECRETPART"}, wantErr: "SBDOMWATCH_WEBHOOK_URL is not an http(s) URL"},
		{name: "secret without url", env: map[string]string{"SBDOMWATCH_WEBHOOK_SECRET": "k"}, wantErr: "is set but"},
		{name: "bad min severity", file: "sinks:\n  discord:\n    min_severity: loud\n", wantErr: "min_severity"},
		{name: "webhook section is not a secret", file: "sinks:\n  webhook:\n    min_severity: high\n", check: func(t *testing.T, c Server) {
			if c.Sinks.Webhook.MinSeverity != "high" || c.Sinks.Webhook.URLEnv != "SBDOMWATCH_WEBHOOK_URL" {
				t.Errorf("webhook: %+v", c.Sinks.Webhook)
			}
		}},
		{name: "webhook url in file", file: "sinks:\n  webhook:\n    webhook_url: https://x\n", wantErr: "looks like a secret"},
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
				if strings.Contains(err.Error(), "SECRETPART") {
					t.Fatalf("error leaks the URL: %v", err)
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

func TestLoadClient(t *testing.T) {
	c, err := LoadClient(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil || c.URL != "" {
		t.Fatalf("missing: %+v, %v", c, err)
	}
	tests := []struct {
		name, content, wantURL, wantErr string
	}{
		{"url", "url: https://watch.example.com\n", "https://watch.example.com", ""},
		{"token rejected", "url: x\ntoken: abc\n", "", "looks like a secret"},
		{"unknown key", "uri: x\n", "", "uri"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadClient(writeFile(t, tt.content))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || c.URL != tt.wantURL {
				t.Fatalf("got %+v, %v", c, err)
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	env := envMap(map[string]string{EnvURL: "http://env"})
	none := envMap(nil)
	tests := []struct {
		flag string
		env  func(string) string
		file Client
		want string
	}{
		{"http://flag", env, Client{URL: "http://file"}, "http://flag"},
		{"", env, Client{URL: "http://file"}, "http://env"},
		{"", none, Client{URL: "http://file"}, "http://file"},
		{"", none, Client{}, DefaultURL},
	}
	for _, tt := range tests {
		if got := ResolveURL(tt.flag, tt.env, tt.file); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestClientConfigPath(t *testing.T) {
	if got := ClientConfigPath(envMap(map[string]string{"XDG_CONFIG_HOME": "/x"})); got != "/x/sbdomwatch/config.yaml" {
		t.Errorf("xdg: %s", got)
	}
	if got := ClientConfigPath(envMap(map[string]string{"HOME": "/home/seb"})); got != "/home/seb/.config/sbdomwatch/config.yaml" {
		t.Errorf("home: %s", got)
	}
}
