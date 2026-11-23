// Package config loads the server configuration from a YAML file and the
// environment. Secrets are read from the environment only.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// Environment variable names.
const (
	EnvConfig     = "SBDOMWATCH_CONFIG"
	EnvListen     = "SBDOMWATCH_LISTEN"
	EnvDBPath     = "SBDOMWATCH_DB_PATH"
	EnvLogLevel   = "SBDOMWATCH_LOG_LEVEL"
	EnvToken      = "SBDOMWATCH_TOKEN"
	EnvURL        = "SBDOMWATCH_URL"
	DefaultConfig = "/etc/sbdomwatch/config.yaml"

	// MinTokenLen is the shortest accepted API token.
	MinTokenLen = 32
)

// Server is the configuration of `sbdomwatch serve`.
type Server struct {
	Listen     string     `yaml:"listen"`
	DBPath     string     `yaml:"db_path"`
	Resolvers  []string   `yaml:"resolvers"`
	RateLimits RateLimits `yaml:"rate_limits"`
	Defaults   Defaults   `yaml:"defaults"`
	Scheduler  Scheduler  `yaml:"scheduler"`
	Sinks      Sinks      `yaml:"sinks"`
	LogLevel   string     `yaml:"log_level"`

	// Secrets, from the environment only.
	Token          string `yaml:"-"`
	DiscordWebhook string `yaml:"-"`
	WebhookURL     string `yaml:"-"`
	WebhookSecret  string `yaml:"-"`
}

// RateLimits caps requests to upstream services.
type RateLimits struct {
	DNSPerSec             float64 `yaml:"dns_per_sec"`
	RDAPPerSecPerRegistry float64 `yaml:"rdap_per_sec_per_registry"`
}

// Scheduler tunes the check loop.
type Scheduler struct {
	Workers int           `yaml:"workers"` // watches checked concurrently
	Tick    time.Duration `yaml:"tick"`    // how often to look for due watches
}

// Defaults are applied to new watches.
type Defaults struct {
	BaselineObservations int           `yaml:"baseline_observations"`
	BaselineGap          time.Duration `yaml:"baseline_gap"`
	DebounceObservations int           `yaml:"debounce_observations"`
	Intervals            Intervals     `yaml:"intervals"`
	CandidateTTL         time.Duration `yaml:"candidate_ttl"`
}

// Intervals is the check interval per watch template.
type Intervals struct {
	Owned      time.Duration `yaml:"owned"`
	Candidate  time.Duration `yaml:"candidate"`
	ThirdParty time.Duration `yaml:"third-party"`
}

// Sinks configures event delivery. A sink is enabled when its URL variable
// is set in the environment.
type Sinks struct {
	Discord DiscordSink `yaml:"discord"`
	Webhook WebhookSink `yaml:"webhook"`
}

// DiscordSink names the environment variable that holds the webhook URL.
type DiscordSink struct {
	WebhookEnv  string `yaml:"webhook_env"`
	MinSeverity string `yaml:"min_severity"`
}

// WebhookSink is the generic JSON webhook (sbalert later). The secret, if
// set, signs every request with HMAC-SHA256.
type WebhookSink struct {
	URLEnv      string `yaml:"url_env"`
	SecretEnv   string `yaml:"secret_env"`
	MinSeverity string `yaml:"min_severity"`
}

// Default returns the built-in configuration.
func Default() Server {
	return Server{
		Listen:    ":8480",
		DBPath:    "/data/sbdomwatch.db",
		Resolvers: []string{"1.1.1.1:53", "9.9.9.9:53"},
		RateLimits: RateLimits{
			DNSPerSec:             20,
			RDAPPerSecPerRegistry: 1,
		},
		Defaults: Defaults{
			BaselineObservations: 3,
			BaselineGap:          3 * time.Minute,
			DebounceObservations: 2,
			Intervals: Intervals{
				Owned:      time.Hour,
				Candidate:  6 * time.Hour,
				ThirdParty: 6 * time.Hour,
			},
			CandidateTTL: 90 * 24 * time.Hour,
		},
		Scheduler: Scheduler{Workers: 8, Tick: 5 * time.Second},
		Sinks: Sinks{
			Discord: DiscordSink{WebhookEnv: "SBDOMWATCH_DISCORD_WEBHOOK", MinSeverity: "medium"},
			Webhook: WebhookSink{URLEnv: "SBDOMWATCH_WEBHOOK_URL", SecretEnv: "SBDOMWATCH_WEBHOOK_SECRET", MinSeverity: "info"},
		},
		LogLevel: "info",
	}
}

// Load builds the server configuration: defaults, then the YAML file at path
// (skipped when path is empty), then environment overrides and secrets.
func Load(path string, getenv func(string) string) (Server, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Server{}, fmt.Errorf("read config: %w", err)
		}
		if err := decode(data, &cfg); err != nil {
			return Server{}, fmt.Errorf("config %s: %w", path, err)
		}
	}
	if v := getenv(EnvListen); v != "" {
		cfg.Listen = v
	}
	if v := getenv(EnvDBPath); v != "" {
		cfg.DBPath = v
	}
	if v := getenv(EnvLogLevel); v != "" {
		cfg.LogLevel = v
	}
	cfg.Token = getenv(EnvToken)
	if cfg.Sinks.Discord.WebhookEnv != "" {
		cfg.DiscordWebhook = getenv(cfg.Sinks.Discord.WebhookEnv)
	}
	if cfg.Sinks.Webhook.URLEnv != "" {
		cfg.WebhookURL = getenv(cfg.Sinks.Webhook.URLEnv)
	}
	if cfg.Sinks.Webhook.SecretEnv != "" {
		cfg.WebhookSecret = getenv(cfg.Sinks.Webhook.SecretEnv)
	}
	if err := cfg.Validate(); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

// secretKeys are keys that must never appear in a config file.
var secretKeys = []string{"token", "webhook", "webhook_url", "password", "secret"}

func decode(data []byte, cfg *Server) error { return decodeStrict(data, cfg) }

// decodeStrict decodes YAML into v, rejecting unknown and secret keys.
func decodeStrict(data []byte, v any) error {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if key := findSecretKey(raw, ""); key != "" {
		return fmt.Errorf("%s looks like a secret; set it through an environment variable, not the config file", key)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

func findSecretKey(m map[string]any, prefix string) string {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		_, isMap := v.(map[string]any)
		for _, s := range secretKeys {
			if strings.EqualFold(k, s) && !isMap {
				return path
			}
		}
		if sub, ok := v.(map[string]any); ok {
			if p := findSecretKey(sub, path); p != "" {
				return p
			}
		}
	}
	return ""
}

// Validate checks that every value is usable.
func (c Server) Validate() error {
	var errs []error
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen %q: %w", c.Listen, err))
	}
	if c.DBPath == "" {
		errs = append(errs, errors.New("db_path is empty"))
	}
	if len(c.Resolvers) == 0 {
		errs = append(errs, errors.New("resolvers is empty"))
	}
	for _, r := range c.Resolvers {
		host, port, err := net.SplitHostPort(r)
		if err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("resolver %q: want host:port", r))
		}
	}
	if c.RateLimits.DNSPerSec <= 0 {
		errs = append(errs, errors.New("rate_limits.dns_per_sec must be > 0"))
	}
	if c.RateLimits.RDAPPerSecPerRegistry <= 0 {
		errs = append(errs, errors.New("rate_limits.rdap_per_sec_per_registry must be > 0"))
	}
	if c.Defaults.BaselineObservations < 1 {
		errs = append(errs, errors.New("defaults.baseline_observations must be >= 1"))
	}
	if c.Defaults.BaselineGap <= 0 {
		errs = append(errs, errors.New("defaults.baseline_gap must be > 0"))
	}
	if c.Defaults.DebounceObservations < 1 {
		errs = append(errs, errors.New("defaults.debounce_observations must be >= 1"))
	}
	for name, d := range map[string]time.Duration{
		"owned":       c.Defaults.Intervals.Owned,
		"candidate":   c.Defaults.Intervals.Candidate,
		"third-party": c.Defaults.Intervals.ThirdParty,
	} {
		if d < time.Minute {
			errs = append(errs, fmt.Errorf("defaults.intervals.%s must be >= 1m", name))
		}
	}
	if c.Scheduler.Workers < 1 || c.Scheduler.Workers > 64 {
		errs = append(errs, errors.New("scheduler.workers must be between 1 and 64"))
	}
	if c.Scheduler.Tick < time.Second || c.Scheduler.Tick > 5*time.Minute {
		errs = append(errs, errors.New("scheduler.tick must be between 1s and 5m"))
	}
	if c.Defaults.CandidateTTL < 24*time.Hour {
		errs = append(errs, errors.New("defaults.candidate_ttl must be >= 24h"))
	}
	if len(c.Token) < MinTokenLen {
		errs = append(errs, fmt.Errorf("%s must be set to at least %d characters (try: openssl rand -hex 32)", EnvToken, MinTokenLen))
	}
	for name, v := range map[string]string{
		"sinks.discord.webhook_env": c.Sinks.Discord.WebhookEnv,
		"sinks.webhook.url_env":     c.Sinks.Webhook.URLEnv,
		"sinks.webhook.secret_env":  c.Sinks.Webhook.SecretEnv,
	} {
		if v != "" && !envKeyRE.MatchString(v) {
			errs = append(errs, fmt.Errorf("%s %q is not a valid variable name", name, v))
		}
	}
	for name, v := range map[string]string{
		"sinks.discord.min_severity": c.Sinks.Discord.MinSeverity,
		"sinks.webhook.min_severity": c.Sinks.Webhook.MinSeverity,
	} {
		if !events.Severity(v).Valid() {
			errs = append(errs, fmt.Errorf("%s %q: want info, medium, high or critical", name, v))
		}
	}
	// URL errors name the variable, never the value: webhook URLs are secrets.
	if c.DiscordWebhook != "" && !isDiscordWebhook(c.DiscordWebhook) {
		errs = append(errs, fmt.Errorf("%s is not a Discord webhook URL (https://discord.com/api/webhooks/...)", c.Sinks.Discord.WebhookEnv))
	}
	if c.WebhookURL != "" && !isHTTPURL(c.WebhookURL) {
		errs = append(errs, fmt.Errorf("%s is not an http(s) URL", c.Sinks.Webhook.URLEnv))
	}
	if c.WebhookSecret != "" && c.WebhookURL == "" {
		errs = append(errs, fmt.Errorf("%s is set but %s is not", c.Sinks.Webhook.SecretEnv, c.Sinks.Webhook.URLEnv))
	}
	if _, err := ParseLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func isDiscordWebhook(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com":
	default:
		return false
	}
	return strings.HasPrefix(u.Path, "/api/webhooks/")
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// WatchDefaults returns the defaults for new watches.
func (c Server) WatchDefaults() watch.Defaults {
	return watch.Defaults{
		Intervals: map[watch.Template]time.Duration{
			watch.TemplateOwned:      c.Defaults.Intervals.Owned,
			watch.TemplateCandidate:  c.Defaults.Intervals.Candidate,
			watch.TemplateThirdParty: c.Defaults.Intervals.ThirdParty,
		},
		CandidateTTL: c.Defaults.CandidateTTL,
	}
}

// ParseLevel maps a log_level string to a slog level.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("log_level %q: want debug, info, warn or error", s)
	}
	return l, nil
}

// LogValue implements slog.LogValuer. Secrets are reported only as set or
// unset, never by value.
func (c Server) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.Listen),
		slog.String("db_path", c.DBPath),
		slog.Any("resolvers", c.Resolvers),
		slog.String("log_level", c.LogLevel),
		slog.Bool("token_set", c.Token != ""),
		slog.Bool("discord_webhook_set", c.DiscordWebhook != ""),
		slog.Bool("webhook_set", c.WebhookURL != ""),
		slog.Bool("webhook_secret_set", c.WebhookSecret != ""),
	)
}
