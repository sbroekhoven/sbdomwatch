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
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
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
)

// Server is the configuration of `sbdomwatch serve`.
type Server struct {
	Listen     string     `yaml:"listen"`
	DBPath     string     `yaml:"db_path"`
	Resolvers  []string   `yaml:"resolvers"`
	RateLimits RateLimits `yaml:"rate_limits"`
	Defaults   Defaults   `yaml:"defaults"`
	Sinks      Sinks      `yaml:"sinks"`
	LogLevel   string     `yaml:"log_level"`

	// Secrets, from the environment only.
	Token          string `yaml:"-"`
	DiscordWebhook string `yaml:"-"`
}

// RateLimits caps requests to upstream services.
type RateLimits struct {
	DNSPerSec             float64 `yaml:"dns_per_sec"`
	RDAPPerSecPerRegistry float64 `yaml:"rdap_per_sec_per_registry"`
}

// Defaults are applied to new watches.
type Defaults struct {
	BaselineObservations int           `yaml:"baseline_observations"`
	BaselineGap          time.Duration `yaml:"baseline_gap"`
	DebounceObservations int           `yaml:"debounce_observations"`
	Intervals            Intervals     `yaml:"intervals"`
}

// Intervals is the check interval per watch template.
type Intervals struct {
	Owned      time.Duration `yaml:"owned"`
	Candidate  time.Duration `yaml:"candidate"`
	ThirdParty time.Duration `yaml:"third-party"`
}

// Sinks configures event delivery.
type Sinks struct {
	Discord DiscordSink `yaml:"discord"`
}

// DiscordSink names the environment variable that holds the webhook URL.
type DiscordSink struct {
	WebhookEnv string `yaml:"webhook_env"`
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
		},
		Sinks:    Sinks{Discord: DiscordSink{WebhookEnv: "SBDOMWATCH_DISCORD_WEBHOOK"}},
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
	if err := cfg.Validate(); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

// secretKeys are keys that must never appear in a config file.
var secretKeys = []string{"token", "webhook", "webhook_url", "password", "secret"}

func decode(data []byte, cfg *Server) error {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if key := findSecretKey(raw, ""); key != "" {
		return fmt.Errorf("%s looks like a secret; set it through an environment variable, not the config file", key)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
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
		for _, s := range secretKeys {
			if strings.EqualFold(k, s) {
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
	if w := c.Sinks.Discord.WebhookEnv; w != "" && !envKeyRE.MatchString(w) {
		errs = append(errs, fmt.Errorf("sinks.discord.webhook_env %q is not a valid variable name", w))
	}
	if _, err := ParseLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
	)
}
