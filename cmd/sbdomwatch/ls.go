package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func (a *app) lsCmd() *cobra.Command {
	var (
		state, tag, origin string
		all                bool
	)
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List watches (archived ones only with --all or --state archived)",
		Args:    usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.newClient()
			if err != nil {
				return err
			}
			ws, err := c.ListWatches(cmd.Context(), client.ListOptions{
				State: watch.State(state), Tag: tag, Origin: watch.OriginKind(origin), All: all,
			})
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, ws)
			}
			tw := newTable(a.stdout)
			fmt.Fprintln(tw, "DOMAIN\tSTATE\tTEMPLATE\tINTERVAL\tNEXT CHECK\tORIGINS\tTAGS")
			for _, w := range ws {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					displayDomain(w.Domain), w.State, w.Template,
					time.Duration(w.IntervalSec)*time.Second, formatTime(w.NextCheckAt),
					originKinds(w.Origins), formatTags(w.Tags))
			}
			return tw.Flush()
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&state, "state", "", "only this state: new, baselining, active, paused or archived")
	fl.StringVar(&tag, "tag", "", "only watches with this tag, key=value")
	fl.StringVar(&origin, "origin", "", "only watches with this origin")
	fl.BoolVar(&all, "all", false, "include archived watches")
	return cmd
}

func originKinds(os []watch.Origin) string {
	set := map[string]bool{}
	for _, o := range os {
		set[string(o.Origin)] = true
	}
	return strings.Join(slices.Sorted(maps.Keys(set)), ",")
}

func formatTags(tags map[string]string) string {
	parts := make([]string, 0, len(tags))
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		parts = append(parts, k+"="+tags[k])
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}
