// Package present turns observations and events into short human-readable
// summaries. The CLI and the MCP server share it.
package present

import (
	"encoding/json"
	"fmt"
	"strings"

	dnscheck "github.com/sbroekhoven/sbdomwatch/internal/check/dns"
	rdapcheck "github.com/sbroekhoven/sbdomwatch/internal/check/rdap"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
)

// Change compares observation i with the next older observation of the
// same check in entries (newest first): "first", "same" or "changed".
func Change(entries []store.TimelineEntry, i int) string {
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

// Observation gives a one-line view of an observation's data.
func Observation(e store.TimelineEntry) string {
	switch e.Check {
	case dnscheck.Name:
		return dns(e)
	case rdapcheck.Name:
		return rdap(e)
	}
	return "hash " + e.Hash[:min(12, len(e.Hash))]
}

func dns(e store.TimelineEntry) string {
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

func rdap(e store.TimelineEntry) string {
	var d rdapcheck.Data
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return "unreadable data"
	}
	if d.State != rdapcheck.StateRegistered {
		return d.State
	}
	parts := []string{"registered"}
	if d.Registrar != "" {
		parts = append(parts, d.Registrar)
	}
	parts = append(parts, fmt.Sprintf("NS:%d", len(d.Nameservers)))
	if d.Expiry != nil {
		parts = append(parts, "expires "+d.Expiry.UTC().Format("2006-01-02"))
	}
	return strings.Join(parts, " ")
}

// EventDetail summarizes what an event is about in one line.
func EventDetail(e events.Event) string {
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
	case e.Type == events.Expiring && p.Expiry != nil:
		return "expires " + p.Expiry.UTC().Format("2006-01-02")
	}
	return "-"
}
