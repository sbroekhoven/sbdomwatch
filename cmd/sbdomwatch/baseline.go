package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *app) confirmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "confirm <domain>",
		Short: "Confirm the baseline of an owned domain after reviewing it",
		Long: "Confirm the baseline of an owned domain. Review it first with\n" +
			"`sbdomwatch history <domain>` (the baseline_complete event lists the inventory).\n" +
			"Event payloads then carry baseline_confirmed: true.",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			w, err := c.Confirm(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, w)
			}
			_, err = fmt.Fprintf(a.stdout, "%s: baseline confirmed by %s\n", displayDomain(w.Domain), w.BaselineConfirmedBy)
			return err
		},
	}
}

func (a *app) rebaselineCmd() *cobra.Command {
	var relearn bool
	cmd := &cobra.Command{
		Use:   "rebaseline <domain>",
		Short: "Accept the current state of a watch as its new baseline",
		Long: "Accept the latest observation as the new baseline: pending changes are dropped,\n" +
			"volatile fields are kept and a confirmation of an owned domain is cleared.\n" +
			"With --relearn the watch baselines again from scratch, which also relearns\n" +
			"which fields are volatile (use it when a field was wrongly marked volatile).",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			w, err := c.Rebaseline(cmd.Context(), args[0], relearn)
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, w)
			}
			if relearn {
				_, err = fmt.Fprintf(a.stdout, "%s: baselining again from scratch (%s)\n", displayDomain(w.Domain), w.State)
				return err
			}
			_, err = fmt.Fprintf(a.stdout, "%s: new baseline accepted\n", displayDomain(w.Domain))
			return err
		},
	}
	cmd.Flags().BoolVar(&relearn, "relearn", false, "baseline again from scratch, relearning volatile fields")
	return cmd
}
