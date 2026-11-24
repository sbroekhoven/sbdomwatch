package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
	"github.com/sbroekhoven/sbdomwatch/internal/present"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

type tools struct {
	api API
}

// Tool inputs. Fields with omitempty are optional in the inferred schema.

type listWatchesIn struct {
	State  string `json:"state,omitempty" jsonschema:"only this state: new, baselining, active, paused or archived"`
	Tag    string `json:"tag,omitempty" jsonschema:"only watches with this tag, as key=value"`
	Origin string `json:"origin,omitempty" jsonschema:"only watches with this origin: manual, typosquat, incident or intel"`
	Stale  bool   `json:"stale,omitempty" jsonschema:"only watches not observed for twice their interval (checks failing)"`
	All    bool   `json:"all,omitempty" jsonschema:"include archived watches"`
}

type domainIn struct {
	Domain string `json:"domain" jsonschema:"the domain, e.g. example.com (Unicode and trailing dots are fine)"`
}

type historyIn struct {
	Domain      string `json:"domain" jsonschema:"the watched domain"`
	Since       string `json:"since,omitempty" jsonschema:"only entries after this: RFC 3339 time, a duration like 24h, or days like 7d"`
	Limit       int    `json:"limit,omitempty" jsonschema:"maximum entries, 1-200 (default 20)"`
	IncludeData bool   `json:"include_data,omitempty" jsonschema:"include the full observation data (larger output)"`
}

type eventsIn struct {
	Since       string   `json:"since,omitempty" jsonschema:"only events after this: RFC 3339 time, 24h or 7d (default 7d)"`
	Types       []string `json:"types,omitempty" jsonschema:"only these event types"`
	Domain      string   `json:"domain,omitempty" jsonschema:"only events of this watched domain"`
	MinSeverity string   `json:"min_severity,omitempty" jsonschema:"minimum severity: info, medium, high or critical"`
	Limit       int      `json:"limit,omitempty" jsonschema:"maximum events, 1-200 (default 50)"`
}

type addIn struct {
	Domain    string            `json:"domain" jsonschema:"the domain to watch"`
	Template  string            `json:"template" jsonschema:"owned (our domain), candidate (lookalike or domain we want) or third-party (someone else's we depend on)"`
	Reason    string            `json:"reason" jsonschema:"why this domain is watched; required, be specific"`
	Origin    string            `json:"origin,omitempty" jsonschema:"manual (default), typosquat, incident or intel; candidates with a manual origin never expire"`
	Reference string            `json:"reference,omitempty" jsonschema:"ticket, incident or mail reference"`
	Tags      map[string]string `json:"tags,omitempty" jsonschema:"tags, key: value"`
	Interval  string            `json:"interval,omitempty" jsonschema:"check interval as a duration like 30m or 6h (default per template)"`
}

type updateIn struct {
	Domain     string            `json:"domain" jsonschema:"the watched domain"`
	Interval   string            `json:"interval,omitempty" jsonschema:"new check interval, e.g. 6h (1m to 168h)"`
	SetTags    map[string]string `json:"set_tags,omitempty" jsonschema:"tags to set, key: value"`
	RemoveTags []string          `json:"remove_tags,omitempty" jsonschema:"tag keys to remove"`
	Paused     *bool             `json:"paused,omitempty" jsonschema:"true pauses checks, false resumes them"`
}

func (t *tools) listWatches(ctx context.Context, _ *mcp.CallToolRequest, in listWatchesIn) (*mcp.CallToolResult, any, error) {
	ws, err := t.api.ListWatches(ctx, client.ListOptions{
		State: watch.State(in.State), Tag: in.Tag, Origin: watch.OriginKind(in.Origin), Stale: in.Stale, All: in.All,
	})
	if err != nil {
		return nil, nil, apiError("", err)
	}
	if len(ws) == 0 {
		return text("No watches match."), nil, nil
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tSTATE\tTEMPLATE\tINTERVAL\tLAST OBSERVED\tORIGINS\tTAGS")
	for _, w := range ws {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", domainLabel(w.Domain), stateLabel(w), w.Template,
			interval(w.IntervalSec), timePtr(w.LastObservedAt), originKinds(w.Origins), tags(w.Tags))
	}
	tw.Flush()
	head := fmt.Sprintf("%d watch(es). State active* = owned domain whose baseline nobody confirmed yet.", len(ws))
	return text(head + "\n" + fence("watchlist", b.String())), nil, nil
}

func (t *tools) getWatch(ctx context.Context, _ *mcp.CallToolRequest, in domainIn) (*mcp.CallToolResult, any, error) {
	w, err := t.api.GetWatch(ctx, in.Domain)
	if err != nil {
		return nil, nil, apiError(in.Domain, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "domain: %s\nstate: %s\ntemplate: %s\ninterval: %s\nnext check: %s\nlast observed: %s\n",
		domainLabel(w.Domain), w.State, w.Template, interval(w.IntervalSec), timeStr(w.NextCheckAt), timePtr(w.LastObservedAt))
	fmt.Fprintf(&b, "baseline completed: %s\n", timePtr(w.BaselineCompletedAt))
	if w.Template == watch.TemplateOwned {
		confirmed := "no (a person should review it and run: sbdomwatch confirm " + w.Domain + ")"
		if w.BaselineConfirmedAt != nil {
			confirmed = timeStr(*w.BaselineConfirmedAt) + " by " + w.BaselineConfirmedBy
		}
		fmt.Fprintf(&b, "baseline confirmed: %s\n", confirmed)
	}
	if len(w.VolatileFields) > 0 {
		fmt.Fprintf(&b, "volatile fields (ignored): %s\n", strings.Join(w.VolatileFields, ", "))
	}
	if w.ExpiresAt != nil {
		fmt.Fprintf(&b, "watch expires (candidate): %s\n", timeStr(*w.ExpiresAt))
	}
	fmt.Fprintf(&b, "tags: %s\norigins:\n", tags(w.Tags))
	for _, o := range w.Origins {
		ref := ""
		if o.Reference != "" {
			ref = ", ref " + o.Reference
		}
		fmt.Fprintf(&b, "  - %s by %s at %s%s: %s\n", o.Origin, o.AddedBy, timeStr(o.AddedAt), ref, o.Reason)
	}
	return text(fence("watch", b.String())), nil, nil
}

func (t *tools) getHistory(ctx context.Context, _ *mcp.CallToolRequest, in historyIn) (*mcp.CallToolResult, any, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, 200)
	h, err := t.api.History(ctx, in.Domain, in.Since, limit)
	if err != nil {
		return nil, nil, apiError(in.Domain, err)
	}
	if len(h.Entries) == 0 {
		return text(fmt.Sprintf("No observations or events for %s yet.", h.Domain)), nil, nil
	}
	var b strings.Builder
	for i, e := range h.Entries {
		if e.Kind == "observation" {
			base := ""
			if e.Baseline {
				base = " (baseline)"
			}
			fmt.Fprintf(&b, "%s observation %s %s%s: %s\n", timeStr(e.At), e.Check, present.Change(h.Entries, i), base, present.Observation(e))
			if in.IncludeData {
				fmt.Fprintf(&b, "  data: %s\n", compact(e.Data))
			}
			continue
		}
		fmt.Fprintf(&b, "%s event %s (%s)\n", timeStr(e.At), e.Type, e.Severity)
		if in.IncludeData {
			fmt.Fprintf(&b, "  payload: %s\n", compact(e.Data))
		}
	}
	head := fmt.Sprintf("History of %s, newest first, %d entries. \"changed\" compares with the previous observation of the same check (TTL changes count; events show what really changed).", h.Domain, len(h.Entries))
	return text(head + "\n" + fence("history", b.String())), nil, nil
}

func (t *tools) listEvents(ctx context.Context, _ *mcp.CallToolRequest, in eventsIn) (*mcp.CallToolResult, any, error) {
	o := client.EventOptions{Since: in.Since, Types: in.Types, Domain: in.Domain, Severity: in.MinSeverity, Limit: in.Limit}
	if o.Since == "" {
		o.Since = "7d"
	}
	if o.Limit <= 0 {
		o.Limit = 50
	}
	o.Limit = min(o.Limit, 200)
	evs, err := t.api.Events(ctx, o)
	if err != nil {
		return nil, nil, apiError(in.Domain, err)
	}
	if len(evs) == 0 {
		return text(fmt.Sprintf("No events since %s.", o.Since)), nil, nil
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tSEVERITY\tTYPE\tDOMAIN\tTEMPLATE\tDETAIL")
	for _, e := range evs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", timeStr(e.OccurredAt), e.Severity, e.Type,
			domainLabel(e.Payload.Domain), e.Payload.Template, present.EventDetail(e))
	}
	tw.Flush()
	head := fmt.Sprintf("%d event(s) since %s, newest first.", len(evs), o.Since)
	return text(head + "\n" + fence("events", b.String())), nil, nil
}

func (t *tools) addWatch(ctx context.Context, _ *mcp.CallToolRequest, in addIn) (*mcp.CallToolResult, any, error) {
	req := watch.AddRequest{
		Domain: in.Domain, Template: watch.Template(in.Template), Reason: in.Reason,
		Origin: watch.OriginKind(in.Origin), Reference: in.Reference, Tags: in.Tags,
	}
	if in.Interval != "" {
		d, err := time.ParseDuration(in.Interval)
		if err != nil || d%time.Second != 0 {
			return nil, nil, fmt.Errorf("interval %q: want a duration like 30m or 6h", in.Interval)
		}
		req.IntervalSec = int(d / time.Second)
	}
	n, err := req.Normalize()
	if err != nil {
		return nil, nil, err // field errors, before any API call
	}
	res, err := t.api.AddWatch(ctx, n)
	if err != nil {
		return nil, nil, apiError(n.Domain, err)
	}
	verb := "unchanged (already watched with this origin and reason)"
	switch {
	case res.Created:
		verb = "added; baselining starts at the next check"
	case res.Changed:
		verb = "merged into the existing watch"
	}
	w := res.Watch
	return text(fmt.Sprintf("%s: %s. Template %s, state %s, interval %s, %d origin(s).",
		domainLabel(w.Domain), verb, w.Template, w.State, interval(w.IntervalSec), len(w.Origins))), nil, nil
}

func (t *tools) updateWatch(ctx context.Context, _ *mcp.CallToolRequest, in updateIn) (*mcp.CallToolResult, any, error) {
	var p watch.PatchRequest
	if in.Interval != "" {
		d, err := time.ParseDuration(in.Interval)
		if err != nil || d%time.Second != 0 {
			return nil, nil, fmt.Errorf("interval %q: want a duration like 30m or 6h", in.Interval)
		}
		sec := int(d / time.Second)
		p.IntervalSec = &sec
	}
	if len(in.SetTags)+len(in.RemoveTags) > 0 {
		p.Tags = map[string]*string{}
		for k, v := range in.SetTags {
			p.Tags[k] = &v
		}
		for _, k := range in.RemoveTags {
			if _, both := in.SetTags[k]; both {
				return nil, nil, fmt.Errorf("tag %q is both set and removed", k)
			}
			p.Tags[k] = nil
		}
	}
	p.Paused = in.Paused
	if p.IntervalSec == nil && p.Tags == nil && p.Paused == nil {
		return nil, nil, fmt.Errorf("nothing to change: give interval, set_tags, remove_tags or paused")
	}
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	w, err := t.api.PatchWatch(ctx, in.Domain, p)
	if err != nil {
		return nil, nil, apiError(in.Domain, err)
	}
	return text(fmt.Sprintf("%s: state %s, interval %s, tags %s.", domainLabel(w.Domain), w.State, interval(w.IntervalSec), tags(w.Tags))), nil, nil
}

func (t *tools) archiveWatch(ctx context.Context, _ *mcp.CallToolRequest, in domainIn) (*mcp.CallToolResult, any, error) {
	w, err := t.api.ArchiveWatch(ctx, in.Domain)
	if err != nil {
		return nil, nil, apiError(in.Domain, err)
	}
	return text(fmt.Sprintf("%s: archived. History is kept; adding it again reactivates it.", domainLabel(w.Domain))), nil, nil
}

// Formatting helpers.

func domainLabel(ascii string) string {
	if u := watch.DisplayDomain(ascii); u != ascii {
		return ascii + " (" + u + ")"
	}
	return ascii
}

func stateLabel(w watch.Watch) string {
	if w.Template == watch.TemplateOwned && w.State == watch.StateActive && w.BaselineConfirmedAt == nil {
		return "active*"
	}
	return string(w.State)
}

func interval(sec int) string { return (time.Duration(sec) * time.Second).String() }

func timeStr(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func timePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return timeStr(*t)
}

func originKinds(os []watch.Origin) string {
	set := map[string]bool{}
	for _, o := range os {
		set[string(o.Origin)] = true
	}
	return strings.Join(slices.Sorted(maps.Keys(set)), ",")
}

func tags(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

func compact(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}
