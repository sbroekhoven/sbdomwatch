package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	"github.com/sbroekhoven/sbdomwatch/internal/config"
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
			if err := api.New(cfg.Listen, log).Run(ctx); err != nil {
				return err
			}
			log.InfoContext(ctx, "stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file (env "+config.EnvConfig+", default "+config.DefaultConfig+" if it exists)")
	return cmd
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
