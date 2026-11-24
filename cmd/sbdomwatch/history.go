package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/present"
)

func (a *app) historyCmd() *cobra.Command {
	var (
		since string
		limit int
	)
	cmd := &cobra.Command{
		Use:   "history <domain>",
		Short: "Show observations and events of a watch, newest first",
		Example: `  sbdomwatch history degiro.nl
  sbdomwatch history degiro.nl --since 7d --limit 200
  sbdomwatch history degiro.nl -o json`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			h, err := c.History(cmd.Context(), args[0], since, limit)
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, h)
			}
			tw := newTable(a.stdout)
			fmt.Fprintln(tw, "TIME\tKIND\tCHECK/TYPE\tCHANGE\tSUMMARY")
			for i, e := range h.Entries {
				switch e.Kind {
				case "observation":
					fmt.Fprintf(tw, "%s\tobservation\t%s\t%s\t%s\n", formatTime(e.At), e.Check, present.Change(h.Entries, i), present.Observation(e))
				default:
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t-\n", formatTime(e.At), e.Kind, e.Type, e.Severity)
				}
			}
			if len(h.Entries) == 0 {
				fmt.Fprintln(tw, "-\t-\t-\t-\tno observations yet")
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only entries after this: RFC 3339 time, duration (24h) or days (7d)")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of entries (1-1000)")
	return cmd
}
