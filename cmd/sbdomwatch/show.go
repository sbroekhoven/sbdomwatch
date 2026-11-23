package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func (a *app) showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <domain>",
		Short: "Show one watch with its origins",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			w, err := c.GetWatch(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, w)
			}
			tw := newTable(a.stdout)
			row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, v) }
			row("Domain:", displayDomain(w.Domain))
			row("State:", string(w.State))
			row("Template:", string(w.Template))
			row("Interval:", (time.Duration(w.IntervalSec) * time.Second).String())
			row("Next check:", formatTime(w.NextCheckAt))
			row("Baseline started:", formatTimePtr(w.BaselineStartedAt))
			row("Baseline completed:", formatTimePtr(w.BaselineCompletedAt))
			if w.ExpiresAt != nil {
				row("Expires:", formatTime(*w.ExpiresAt))
			}
			row("Tags:", formatTags(w.Tags))
			if len(w.VolatileFields) > 0 {
				row("Volatile fields:", strings.Join(w.VolatileFields, ", "))
			}
			row("Created:", formatTime(w.CreatedAt))
			row("Updated:", formatTime(w.UpdatedAt))
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(a.stdout)
			tw = newTable(a.stdout)
			fmt.Fprintln(tw, "ORIGIN\tREASON\tREFERENCE\tADDED BY\tADDED AT")
			for _, o := range w.Origins {
				ref := o.Reference
				if ref == "" {
					ref = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", o.Origin, o.Reason, ref, o.AddedBy, formatTime(o.AddedAt))
			}
			return tw.Flush()
		},
	}
}
