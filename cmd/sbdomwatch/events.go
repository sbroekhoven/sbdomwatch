package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
)

func (a *app) eventsCmd() *cobra.Command {
	var o client.EventOptions
	cmd := &cobra.Command{
		Use:   "events",
		Short: "List events, newest first",
		Example: `  sbdomwatch events --since 24h
  sbdomwatch events --since 7d --type mx_appeared --type ns_changed
  sbdomwatch events --domain degiro.nl --severity high`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			evs, err := c.Events(cmd.Context(), o)
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, evs)
			}
			tw := newTable(a.stdout)
			fmt.Fprintln(tw, "TIME\tSEVERITY\tTYPE\tDOMAIN\tDETAIL")
			for _, e := range evs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", formatTime(e.OccurredAt), e.Severity, e.Type,
					displayDomain(e.Payload.Domain), eventDetail(e))
			}
			if len(evs) == 0 {
				fmt.Fprintln(tw, "-\t-\t-\t-\tno events")
			}
			return tw.Flush()
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&o.Since, "since", "24h", "only events after this: RFC 3339 time, duration (24h) or days (7d); empty for all")
	fl.StringSliceVar(&o.Types, "type", nil, "only these event types, repeatable or comma-separated")
	fl.StringVar(&o.Domain, "domain", "", "only events of this watch")
	fl.StringVar(&o.Severity, "severity", "", "minimum severity: info, medium, high or critical")
	fl.IntVar(&o.Limit, "limit", 100, "maximum number of events (1-1000)")
	return cmd
}

// eventDetail summarizes what an event is about in one line.
func eventDetail(e events.Event) string {
	p := e.Payload
	switch {
	case p.Change != nil:
		var parts []string
		for _, v := range p.Change.Added {
			parts = append(parts, "+"+v)
		}
		for _, v := range p.Change.Removed {
			parts = append(parts, "-"+v)
		}
		s := p.Change.Path + " " + strings.Join(parts, " ")
		if len(s) > 100 {
			s = s[:99] + "…"
		}
		return s
	case e.Type == events.BaselineComplete:
		s := fmt.Sprintf("%d observation(s), %d fields", p.Observations, len(p.Inventory))
		if len(p.VolatileFields) > 0 {
			s += ", volatile " + strings.Join(p.VolatileFields, ",")
		}
		return s
	}
	return "-"
}
