package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/store"
)

// History limits.
const (
	defaultHistoryLimit = 50
	maxHistoryLimit     = 1000
)

// HistoryResponse is the body of GET /v1/watches/{domain}/history.
type HistoryResponse struct {
	Domain  string                `json:"domain"`
	Entries []store.TimelineEntry `json:"entries"` // newest first
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	d, err := pathDomain(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	q := r.URL.Query()
	since, err := ParseSince(q.Get("since"), s.now())
	if err != nil {
		s.writeErr(w, r, badRequest("since: %v", err))
		return
	}
	limit := defaultHistoryLimit
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 1 || limit > maxHistoryLimit {
			s.writeErr(w, r, badRequest("limit: want 1..%d", maxHistoryLimit))
			return
		}
	}
	entries, err := s.store.History(r.Context(), d, since, limit)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, HistoryResponse{Domain: d, Entries: entries})
}

// ParseSince accepts an RFC 3339 time, a Go duration ("36h") or a number
// of days ("7d"), the latter two counted back from now. Empty means no
// lower bound.
func ParseSince(v string, now time.Time) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return time.Time{}, errSince
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour).UTC(), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return time.Time{}, errSince
	}
	return now.Add(-d).UTC(), nil
}

var errSince = errors.New("want an RFC 3339 time, a duration like 24h, or days like 7d")
