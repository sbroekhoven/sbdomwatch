package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
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
					fmt.Fprintf(tw, "%s\tobservation\t%s\t%s\t%s\n", formatTime(e.At), e.Check, change(h.Entries, i), summarize(e))
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

// change compares an observation with the next older one of the same check
// in the list.
func change(entries []store.TimelineEntry, i int) string {
	for _, older := range entries[i+1:] {
		if older.Kind == "observation" && older.Check == entries[i].Check {
			if older.Hash == entries[i].Hash {
				return "same"
			}
			return "changed"
		}
	}
	return "first"
}

// summarize gives a one-line view of an observation's data.
func summarize(e store.TimelineEntry) string {
	if e.Check != dnscheck.Name {
		return "hash " + e.Hash[:min(12, len(e.Hash))]
	}
	var d dnscheck.Data
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return "unreadable data"
	}
	var parts []string
	for _, t := range dnscheck.Types {
		name := dnscheck.TypeName(t)
		set, ok := d.Records[name]
		switch {
		case !ok:
			continue
		case set.Error != "":
			parts = append(parts, name+":error")
		case set.Rcode != "" && set.Rcode != "NOERROR":
			parts = append(parts, name+":"+set.Rcode)
		case len(set.Values) > 0:
			parts = append(parts, fmt.Sprintf("%s:%d", name, len(set.Values)))
		}
	}
	if len(parts) == 0 {
		return "no records"
	}
	return strings.Join(parts, " ")
}
