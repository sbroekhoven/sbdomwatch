package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// stateCmd builds pause, resume and archive, which all take one domain and
// print the resulting state.
func (a *app) stateCmd(use, short string, fn func(ctx context.Context, c *client.Client, domain string) (watch.Watch, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <domain>",
		Short: short,
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			w, err := fn(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, w)
			}
			_, err = fmt.Fprintf(a.stdout, "%s: %s\n", displayDomain(w.Domain), w.State)
			return err
		},
	}
}

func (a *app) pauseCmd() *cobra.Command {
	return a.stateCmd("pause", "Stop checking a watch until it is resumed", func(ctx context.Context, c *client.Client, d string) (watch.Watch, error) {
		yes := true
		return c.PatchWatch(ctx, d, watch.PatchRequest{Paused: &yes})
	})
}

func (a *app) resumeCmd() *cobra.Command {
	return a.stateCmd("resume", "Resume a paused watch", func(ctx context.Context, c *client.Client, d string) (watch.Watch, error) {
		no := false
		return c.PatchWatch(ctx, d, watch.PatchRequest{Paused: &no})
	})
}

func (a *app) archiveCmd() *cobra.Command {
	return a.stateCmd("archive", "Archive a watch; history is kept, add it again to reactivate", func(ctx context.Context, c *client.Client, d string) (watch.Watch, error) {
		return c.ArchiveWatch(ctx, d)
	})
}
