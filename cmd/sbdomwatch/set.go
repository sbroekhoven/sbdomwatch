package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func (a *app) setCmd() *cobra.Command {
	var (
		interval time.Duration
		tags     []string
		untags   []string
	)
	cmd := &cobra.Command{
		Use:   "set <domain>",
		Short: "Change the check interval or tags of a watch",
		Example: `  sbdomwatch set suspiciousbytes.com --interval 6h
  sbdomwatch set degir0.com --tag status=reported --untag triage`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := patchFromFlags(cmd.Flags().Changed("interval"), interval, tags, untags)
			if err != nil {
				return err
			}
			c, err := a.newClient()
			if err != nil {
				return err
			}
			w, err := c.PatchWatch(cmd.Context(), args[0], p)
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, w)
			}
			_, err = fmt.Fprintf(a.stdout, "%s: interval %s, tags %s\n", displayDomain(w.Domain),
				time.Duration(w.IntervalSec)*time.Second, formatTags(w.Tags))
			return err
		},
	}
	fl := cmd.Flags()
	fl.DurationVar(&interval, "interval", 0, "check interval, e.g. 30m or 6h (1m to 168h)")
	fl.StringArrayVar(&tags, "tag", nil, "set a tag, key=value, repeatable")
	fl.StringArrayVar(&untags, "untag", nil, "remove a tag by key, repeatable")
	return cmd
}

// patchFromFlags builds a validated patch; problems are usage errors.
func patchFromFlags(intervalSet bool, interval time.Duration, tags, untags []string) (watch.PatchRequest, error) {
	var p watch.PatchRequest
	if intervalSet {
		if interval%time.Second != 0 {
			return p, usageError(errors.New("--interval must be whole seconds"))
		}
		sec := int(interval / time.Second)
		p.IntervalSec = &sec
	}
	set, err := parseTags(tags)
	if err != nil {
		return p, usageError(err)
	}
	if len(set)+len(untags) > 0 {
		p.Tags = map[string]*string{}
		for k, v := range set {
			p.Tags[k] = &v
		}
		for _, k := range untags {
			if _, both := set[k]; both {
				return p, usageError(fmt.Errorf("tag %q is both set and removed", k))
			}
			p.Tags[k] = nil
		}
	}
	if p.IntervalSec == nil && p.Tags == nil {
		return p, usageError(errors.New("nothing to change: use --interval, --tag or --untag"))
	}
	if err := p.Validate(); err != nil {
		return p, usageError(err)
	}
	return p, nil
}
