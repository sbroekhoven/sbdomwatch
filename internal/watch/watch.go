// Package watch defines watches, their lifecycle and the rules for adding,
// merging and changing them. It has no I/O.
package watch

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// State is the lifecycle state of a watch.
type State string

// Lifecycle states.
const (
	StateNew        State = "new"
	StateBaselining State = "baselining"
	StateActive     State = "active"
	StatePaused     State = "paused"
	StateArchived   State = "archived"
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StateNew, StateBaselining, StateActive, StatePaused, StateArchived:
		return true
	}
	return false
}

// Template describes the relationship to a domain and sets defaults.
type Template string

// Templates, in increasing order of importance.
const (
	TemplateCandidate  Template = "candidate"
	TemplateThirdParty Template = "third-party"
	TemplateOwned      Template = "owned"
)

func (t Template) rank() int {
	switch t {
	case TemplateCandidate:
		return 1
	case TemplateThirdParty:
		return 2
	case TemplateOwned:
		return 3
	}
	return 0
}

// Valid reports whether t is a known template.
func (t Template) Valid() bool { return t.rank() > 0 }

// OriginKind says why a domain is watched.
type OriginKind string

// Origin kinds.
const (
	OriginManual    OriginKind = "manual"
	OriginTyposquat OriginKind = "typosquat"
	OriginIncident  OriginKind = "incident"
	OriginIntel     OriginKind = "intel"
)

// Valid reports whether o is a known origin kind.
func (o OriginKind) Valid() bool {
	switch o {
	case OriginManual, OriginTyposquat, OriginIncident, OriginIntel:
		return true
	}
	return false
}

// Origin records who added a watch and why.
type Origin struct {
	Origin    OriginKind `json:"origin"`
	Reason    string     `json:"reason"`
	Reference string     `json:"reference,omitempty"`
	AddedBy   string     `json:"added_by"`
	AddedAt   time.Time  `json:"added_at"`
}

// Watch is one watched domain.
type Watch struct {
	ID                  int64             `json:"id"`
	Domain              string            `json:"domain"`
	Template            Template          `json:"template"`
	State               State             `json:"state"`
	IntervalSec         int               `json:"interval_sec"`
	NextCheckAt         time.Time         `json:"next_check_at"`
	BaselineStartedAt   *time.Time        `json:"baseline_started_at,omitempty"`
	BaselineCompletedAt *time.Time        `json:"baseline_completed_at,omitempty"`
	BaselineConfirmedAt *time.Time        `json:"baseline_confirmed_at,omitempty"` // owned: a person checked the baseline
	BaselineConfirmedBy string            `json:"baseline_confirmed_by,omitempty"`
	LastObservedAt      *time.Time        `json:"last_observed_at,omitempty"`
	VolatileFields      []string          `json:"volatile_fields"`
	Tags                map[string]string `json:"tags"`
	ExpiresAt           *time.Time        `json:"expires_at,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	Origins             []Origin          `json:"origins"`
}

// Limits on user input.
const (
	MaxReasonLen    = 1000
	MaxReferenceLen = 256
	MaxTags         = 32
	MaxTagValueLen  = 256
	MaxActorLen     = 64
	MinIntervalSec  = 60
	MaxIntervalSec  = 7 * 24 * 3600
)

var (
	tagKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	actorRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)
)

// FieldError is a validation problem with one input field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError lists every invalid field of a request.
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return "invalid request: " + strings.Join(parts, "; ")
}

func (e *ValidationError) add(field, format string, a ...any) {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: fmt.Sprintf(format, a...)})
}

func (e *ValidationError) err() error {
	if len(e.Fields) == 0 {
		return nil
	}
	return e
}

// Errors for operations that do not fit the watch's current state. The API
// answers them with 409 Conflict.
var (
	ErrArchived   = errors.New("watch is archived")
	ErrNotOwned   = errors.New("only owned watches have a baseline to confirm")
	ErrNoBaseline = errors.New("the baseline is not complete yet")
)

// AddRequest is the input for adding or merging a watch.
type AddRequest struct {
	Domain      string            `json:"domain"`
	Template    Template          `json:"template"`
	Reason      string            `json:"reason"`
	Reference   string            `json:"reference,omitempty"`
	Origin      OriginKind        `json:"origin,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	IntervalSec int               `json:"interval_sec,omitempty"`
}

// Normalize validates the request and returns a canonical copy: normalized
// domain, trimmed text and the default origin.
func (r AddRequest) Normalize() (AddRequest, error) {
	var ve ValidationError
	out := r
	d, err := NormalizeDomain(r.Domain)
	if err != nil {
		ve.add("domain", "%s", strings.TrimPrefix(err.Error(), ErrInvalidDomain.Error()+" "))
	}
	out.Domain = d
	if !r.Template.Valid() {
		ve.add("template", "must be owned, candidate or third-party")
	}
	out.Reason = strings.TrimSpace(r.Reason)
	switch {
	case out.Reason == "":
		ve.add("reason", "is required")
	case utf8.RuneCountInString(out.Reason) > MaxReasonLen:
		ve.add("reason", "longer than %d characters", MaxReasonLen)
	case hasControl(out.Reason):
		ve.add("reason", "contains control characters")
	}
	out.Reference = strings.TrimSpace(r.Reference)
	if utf8.RuneCountInString(out.Reference) > MaxReferenceLen || hasControl(out.Reference) {
		ve.add("reference", "longer than %d characters or contains control characters", MaxReferenceLen)
	}
	if out.Origin == "" {
		out.Origin = OriginManual
	}
	if !out.Origin.Valid() {
		ve.add("origin", "must be manual, typosquat, incident or intel")
	}
	if r.IntervalSec != 0 {
		if err := validateInterval(r.IntervalSec); err != nil {
			ve.add("interval_sec", "%v", err)
		}
	}
	out.Tags = nil
	if len(r.Tags) > 0 {
		out.Tags = make(map[string]string, len(r.Tags))
		for k, v := range r.Tags {
			if err := ValidateTag(k, v); err != nil {
				ve.add("tags."+k, "%v", err)
			}
			out.Tags[k] = strings.TrimSpace(v)
		}
		if len(r.Tags) > MaxTags {
			ve.add("tags", "more than %d tags", MaxTags)
		}
	}
	if err := ve.err(); err != nil {
		return AddRequest{}, err
	}
	return out, nil
}

// PatchRequest changes a watch. Nil fields are left alone; a nil tag value
// removes that tag.
type PatchRequest struct {
	Paused      *bool              `json:"paused,omitempty"`
	IntervalSec *int               `json:"interval_sec,omitempty"`
	Tags        map[string]*string `json:"tags,omitempty"`
}

// Validate checks the patch.
func (p PatchRequest) Validate() error {
	var ve ValidationError
	if p.IntervalSec != nil {
		if err := validateInterval(*p.IntervalSec); err != nil {
			ve.add("interval_sec", "%v", err)
		}
	}
	for k, v := range p.Tags {
		val := ""
		if v != nil {
			val = *v
		}
		if err := ValidateTag(k, val); err != nil {
			ve.add("tags."+k, "%v", err)
		}
	}
	return ve.err()
}

// NormalizeActor validates who performs an action. Empty becomes "api".
func NormalizeActor(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "api", nil
	}
	if len(s) > MaxActorLen || !actorRE.MatchString(s) {
		return "", &ValidationError{Fields: []FieldError{{Field: "actor", Message: "must be 1-64 characters of A-Z a-z 0-9 . _ @ + -"}}}
	}
	return s, nil
}

func validateInterval(sec int) error {
	if sec < MinIntervalSec || sec > MaxIntervalSec {
		return fmt.Errorf("must be between %d and %d seconds", MinIntervalSec, MaxIntervalSec)
	}
	return nil
}

// ValidateTag checks one tag key and value.
func ValidateTag(k, v string) error {
	if !tagKeyRE.MatchString(k) {
		return errors.New("key must match [a-z0-9][a-z0-9_.-]{0,62}")
	}
	if utf8.RuneCountInString(v) > MaxTagValueLen || hasControl(v) {
		return fmt.Errorf("value longer than %d characters or contains control characters", MaxTagValueLen)
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}
