package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	"github.com/sbroekhoven/sbdomwatch/internal/check"
	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	rdapcheck "github.com/sbroekhoven/sbdomwatch/internal/check/rdap"
	"github.com/sbroekhoven/sbdomwatch/internal/config"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/ratelimit"
	"github.com/sbroekhoven/sbdomwatch/internal/sched"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func (a *app) serveCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the sbdomwatch service",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveConfigPath(configPath, a.getenv(config.EnvConfig))
			if err != nil {
				return err
			}
			cfg, err := config.Load(path, a.getenv)
			if err != nil {
				return err
			}
			level, _ := config.ParseLevel(cfg.LogLevel) // validated by Load
			log := slog.New(slog.NewJSONHandler(a.stderr, &slog.HandlerOptions{Level: level}))

			ctx := cmd.Context()
			log.InfoContext(ctx, "starting sbdomwatch", "version", a.version, "config_file", path, "config", cfg)
			st, err := store.Open(ctx, cfg.DBPath, store.Options{})
			if err != nil {
				return err
			}
			defer st.Close()
			srv := api.New(cfg.Listen, api.Deps{Store: st, Token: cfg.Token, Defaults: cfg.WatchDefaults(), Log: log})
			dnsLimiter := ratelimit.New(cfg.RateLimits.DNSPerSec, int(math.Ceil(cfg.RateLimits.DNSPerSec)), nil)
			sinks := buildSinks(cfg, a.version)
			outbox := events.NewDispatcher(events.DispatcherConfig{
				Store: st,
				Sinks: sinks,
				Log:   log.With("component", "outbox"),
			})
			sc := sched.New(sched.Config{
				Store: st,
				Checks: []check.Check{
					dnscheck.New(dnscheck.Config{Resolvers: cfg.Resolvers, Limiter: dnsLimiter}),
					rdapcheck.New(rdapcheck.NewClient(cfg.RateLimits.RDAPPerSecPerRegistry, "sbdomwatch/"+a.version), nil),
				},
				Extractors: map[string]diff.Extractor{dnscheck.Name: dnscheck.Facts, rdapcheck.Name: rdapcheck.Facts},
				Lifecycle: watch.LifecycleConfig{
					BaselineObservations: cfg.Defaults.BaselineObservations,
					Debounce:             cfg.Defaults.DebounceObservations,
				},
				BaselineGap: cfg.Defaults.BaselineGap,
				Route:       events.Router(sinks),
				OnEvents:    outbox.Notify,
				Log:         log.With("component", "scheduler"),
				Workers:     cfg.Scheduler.Workers,
				Tick:        cfg.Scheduler.Tick,
			})
			if err := runAll(ctx, srv.Run, sc.Run, outbox.Run); err != nil {
				return err
			}
			log.InfoContext(ctx, "stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (env "+config.EnvConfig+", default "+config.DefaultConfig+" if it exists)")
	return cmd
}

// buildSinks returns the sinks whose URL is configured.
func buildSinks(cfg config.Server, version string) []events.Sink {
	client := &http.Client{Timeout: 15 * time.Second}
	ua := "sbdomwatch/" + version
	var sinks []events.Sink
	if cfg.DiscordWebhook != "" {
		sinks = append(sinks, events.NewDiscord(cfg.DiscordWebhook, events.Severity(cfg.Sinks.Discord.MinSeverity), client, ua))
	}
	if cfg.WebhookURL != "" {
		sinks = append(sinks, events.NewWebhook(cfg.WebhookURL, cfg.WebhookSecret, events.Severity(cfg.Sinks.Webhook.MinSeverity), client, ua))
	}
	return sinks
}

// runAll runs every fn until ctx is cancelled or one of them returns, then
// cancels the rest and returns the first error.
func runAll(ctx context.Context, fns ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, len(fns))
	for _, fn := range fns {
		go func() { errc <- fn(ctx) }()
	}
	var first error
	for range fns {
		if err := <-errc; err != nil && first == nil {
			first = err
		}
		cancel()
	}
	return first
}

// resolveConfigPath picks the config file: the flag, then the environment,
// then the default path if it exists. An explicit path must exist; without
// one the built-in defaults are used.
func resolveConfigPath(flag, env string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env != "" {
		return env, nil
	}
	_, err := os.Stat(config.DefaultConfig)
	switch {
	case err == nil:
		return config.DefaultConfig, nil
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	default:
		return "", fmt.Errorf("stat %s: %w", config.DefaultConfig, err)
	}
}
