// Package events defines the event contract: types, severities and the
// payload that sinks and API clients (sbalert, sbsquat, sbcti) receive. It is
// domain neutral and imports no other sbdomwatch package except diff.
package events

import (
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

// Type is an event type.
type Type string

// Event types.
const (
	BaselineComplete Type = "baseline_complete"
	Registered       Type = "registered"
	Dropped          Type = "dropped"
	MXAppeared       Type = "mx_appeared"
	NSChanged        Type = "ns_changed"
	RegistrarChanged Type = "registrar_changed"
	RecordAdded      Type = "record_added"
	RecordChanged    Type = "record_changed"
	RecordRemoved    Type = "record_removed"
	Expiring         Type = "expiring"
	DanglingCNAME    Type = "dangling_cname"
)

// Severity orders events by urgency.
type Severity string

// Severities.
const (
	Info     Severity = "info"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// OriginRef says why the domain is watched.
type OriginRef struct {
	Origin    string `json:"origin"`
	Reason    string `json:"reason"`
	Reference string `json:"reference,omitempty"`
}

// Payload is the event body. Fields not relevant to a type are omitted.
type Payload struct {
	Domain   string            `json:"domain"`
	Template string            `json:"template"`
	Origins  []OriginRef       `json:"origins"`
	Tags     map[string]string `json:"tags,omitempty"`

	// Change is set for change events.
	Change *diff.Change `json:"change,omitempty"`

	// Inventory and VolatileFields are set for baseline_complete.
	Inventory      map[string][]string `json:"inventory,omitempty"`
	VolatileFields []string            `json:"volatile_fields,omitempty"`
	Observations   int                 `json:"observations,omitempty"`
}

// Event is one stored event.
type Event struct {
	ID         int64     `json:"id"`
	WatchID    int64     `json:"watch_id"`
	Type       Type      `json:"type"`
	Severity   Severity  `json:"severity"`
	OccurredAt time.Time `json:"occurred_at"`
	Payload    Payload   `json:"payload"`
}

// ForChange maps a diff change to an event type and severity. owned raises
// the severity of nameserver changes.
func ForChange(c diff.Change, owned bool) (Type, Severity) {
	field := c.Path
	if i := strings.LastIndexByte(field, '.'); i >= 0 {
		field = field[i+1:]
	}
	isDNS := strings.HasPrefix(c.Path, "dns.")
	switch {
	case isDNS && field == "MX" && c.Kind == diff.Added:
		return MXAppeared, High
	case isDNS && field == "NS":
		if owned {
			return NSChanged, Critical
		}
		return NSChanged, High
	case c.Kind == diff.Added:
		return RecordAdded, Medium
	case c.Kind == diff.Removed:
		return RecordRemoved, Medium
	default:
		return RecordChanged, Medium
	}
}
