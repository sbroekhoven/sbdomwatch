package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/config"
)

// app holds what the subcommands share. It replaces global state.
type app struct {
	version   string
	stdout    io.Writer
	stderr    io.Writer
	lookupEnv func(string) (string, bool)

	// Global flags.
	envFile string
	url     string
	output  string

	// getenv resolves variables from the process environment, then the
	// .env file. Set before any subcommand runs.
	getenv func(string) string
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sbdomwatch",
		Short:         "Domain and DNS watcher",
		Long:          "sbdomwatch watches domains and DNS and reports every meaningful change as an event.\n`sbdomwatch serve` runs the service; the other subcommands are the CLI.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: a.setup,
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError(err) })
	root.CompletionOptions.DisableDefaultCmd = true

	pf := root.PersistentFlags()
	pf.StringVar(&a.envFile, "env-file", ".env", "file with environment variables; a missing file is ignored")
	pf.StringVar(&a.url, "url", "", "API base URL (env "+config.EnvURL+")")
	pf.StringVarP(&a.output, "output", "o", "table", "output format: table or json")

	root.AddCommand(
		a.serveCmd(), a.versionCmd(),
		a.addCmd(), a.importCmd(), a.lsCmd(), a.showCmd(), a.historyCmd(), a.eventsCmd(),
		a.pauseCmd(), a.resumeCmd(), a.archiveCmd(),
		a.confirmCmd(), a.rebaselineCmd(), a.setCmd(),
	)
	return root
}

func (a *app) setup(_ *cobra.Command, _ []string) error {
	if a.output != "table" && a.output != "json" {
		return usageError(fmt.Errorf("invalid --output %q: want table or json", a.output))
	}
	file, err := config.ReadDotenv(a.envFile)
	if err != nil {
		return err
	}
	a.getenv = config.Getenv(a.lookupEnv, file)
	return nil
}

// usageArgs marks argument validation errors as usage errors.
func usageArgs(fn cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := fn(cmd, args); err != nil {
			return usageError(err)
		}
		return nil
	}
}
