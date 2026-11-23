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

// rank orders severities; unknown ones rank lowest.
func (s Severity) rank() int {
	switch s {
	case Info:
		return 1
	case Medium:
		return 2
	case High:
		return 3
	case Critical:
		return 4
	}
	return 0
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.rank() > 0 }

// AtLeast reports whether s is min or more severe.
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// AtLeast returns the severities at least as severe as min.
func AtLeast(min Severity) []Severity {
	var out []Severity
	for _, s := range []Severity{Info, Medium, High, Critical} {
		if s.AtLeast(min) {
			out = append(out, s)
		}
	}
	return out
}

// ValidType reports whether t is a known event type.
func ValidType(t Type) bool {
	switch t {
	case BaselineComplete, Registered, Dropped, MXAppeared, NSChanged, RegistrarChanged,
		RecordAdded, RecordChanged, RecordRemoved, Expiring, DanglingCNAME:
		return true
	}
	return false
}

// Delivery is one pending outbox row: an event for one sink.
type Delivery struct {
	Event    Event
	Sink     string
	Attempts int // failed attempts so far
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
