package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// addFlags are shared by add and import.
type addFlags struct {
	template  string
	reason    string
	reference string
	origin    string
	tags      []string
	interval  time.Duration
}

func (f *addFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.template, "template", "", "owned, candidate or third-party (required)")
	fl.StringVar(&f.reason, "reason", "", "why this domain is watched (required)")
	fl.StringVar(&f.reference, "reference", "", "ticket, incident or mail reference")
	fl.StringVar(&f.origin, "origin", string(watch.OriginManual), "manual, typosquat, incident or intel")
	fl.StringArrayVar(&f.tags, "tag", nil, "tag as key=value, repeatable")
	fl.DurationVar(&f.interval, "interval", 0, "check interval, e.g. 30m (default: per template)")
}

// request builds a normalized AddRequest for domain. Problems are usage
// errors (exit code 2).
func (f *addFlags) request(domain string) (watch.AddRequest, error) {
	if f.template == "" {
		return watch.AddRequest{}, usageError(errors.New("--template is required"))
	}
	if strings.TrimSpace(f.reason) == "" {
		return watch.AddRequest{}, usageError(errors.New("--reason is required and must not be empty"))
	}
	tags, err := parseTags(f.tags)
	if err != nil {
		return watch.AddRequest{}, usageError(err)
	}
	if f.interval%time.Second != 0 {
		return watch.AddRequest{}, usageError(errors.New("--interval must be whole seconds"))
	}
	req := watch.AddRequest{
		Domain:      domain,
		Template:    watch.Template(f.template),
		Reason:      f.reason,
		Reference:   f.reference,
		Origin:      watch.OriginKind(f.origin),
		Tags:        tags,
		IntervalSec: int(f.interval / time.Second),
	}
	n, err := req.Normalize()
	if err != nil {
		return watch.AddRequest{}, usageError(err)
	}
	return n, nil
}

func parseTags(in []string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	tags := make(map[string]string, len(in))
	for _, t := range in {
		k, v, ok := strings.Cut(t, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--tag %q: want key=value", t)
		}
		tags[k] = v
	}
	return tags, nil
}

func (a *app) addCmd() *cobra.Command {
	var f addFlags
	cmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a domain to the watch list, or merge into an existing watch",
		Example: `  sbdomwatch add degir0.com --template candidate --reason "seen in CT, profile degiro" --tag profile=degiro
  sbdomwatch add degiro.nl --template owned --reason "company domain"`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := f.request(args[0])
			if err != nil {
				return err
			}
			c, err := a.newClient()
			if err != nil {
				return err
			}
			res, err := c.AddWatch(cmd.Context(), req)
			if err != nil {
				return err
			}
			if a.output == "json" {
				return writeJSON(a.stdout, res)
			}
			verb := "unchanged"
			switch {
			case res.Created:
				verb = "added"
			case res.Changed:
				verb = "merged"
			}
			_, err = fmt.Fprintf(a.stdout, "%s %s (%s, %s, %d origin(s))\n", verb, displayDomain(res.Watch.Domain),
				res.Watch.Template, res.Watch.State, len(res.Watch.Origins))
			return err
		},
	}
	f.register(cmd)
	return cmd
}
