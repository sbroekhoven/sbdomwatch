package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// Event list limits.
const (
	defaultEventLimit = 100
	maxEventLimit     = 1000
)

// EventsResponse is the body of GET /v1/events.
type EventsResponse struct {
	Events []events.Event `json:"events"` // newest first
}

// handleEvents serves GET /v1/events with the filters since (RFC 3339, 24h,
// 7d), type (comma-separated), watch (domain), severity (minimum) and limit.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.EventFilter
	var ve watch.ValidationError
	since, err := ParseSince(q.Get("since"), s.now())
	if err != nil {
		ve.Fields = append(ve.Fields, watch.FieldError{Field: "since", Message: err.Error()})
	}
	f.Since = since
	if v := q.Get("type"); v != "" {
		for _, t := range strings.Split(v, ",") {
			typ := events.Type(strings.TrimSpace(t))
			if !events.ValidType(typ) {
				ve.Fields = append(ve.Fields, watch.FieldError{Field: "type", Message: "unknown event type " + strconv.Quote(string(typ))})
				continue
			}
			f.Types = append(f.Types, typ)
		}
	}
	if v := q.Get("watch"); v != "" {
		d, err := watch.NormalizeDomain(v)
		if err != nil {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "watch", Message: err.Error()})
		}
		f.Domain = d
	}
	if v := q.Get("severity"); v != "" {
		f.MinSeverity = events.Severity(v)
		if !f.MinSeverity.Valid() {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "severity", Message: "want info, medium, high or critical"})
		}
	}
	f.Limit = defaultEventLimit
	if v := q.Get("limit"); v != "" {
		f.Limit, err = strconv.Atoi(v)
		if err != nil || f.Limit < 1 || f.Limit > maxEventLimit {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "limit", Message: "want 1.." + strconv.Itoa(maxEventLimit)})
		}
	}
	if len(ve.Fields) > 0 {
		s.writeErr(w, r, &ve)
		return
	}
	evs, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, EventsResponse{Events: evs})
}
