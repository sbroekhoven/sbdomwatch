package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// RebaselineRequest is the optional body of POST /v1/watches/{domain}:rebaseline.
type RebaselineRequest struct {
	// Relearn restarts baselining from scratch (and relearns volatile
	// fields) instead of accepting the latest observation.
	Relearn bool `json:"relearn,omitempty"`
}

// handleAction serves POST /v1/watches/{domain}:{verb}. ServeMux wildcards
// must be whole segments, so the verb is split off here; a domain never
// contains a colon.
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
	i := strings.LastIndexByte(target, ':')
	if i < 0 {
		writeError(w, http.StatusMethodNotAllowed, CodeInvalidArgument, "use :confirm or :rebaseline", nil)
		return
	}
	raw, verb := target[:i], target[i+1:]
	d, err := watch.NormalizeDomain(raw)
	if err != nil {
		s.writeErr(w, r, &watch.ValidationError{Fields: []watch.FieldError{{Field: "domain", Message: err.Error()}}})
		return
	}
	who, err := actor(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	switch verb {
	case "confirm":
		s.confirm(w, r, d, who)
	case "rebaseline":
		var req RebaselineRequest
		if err := decodeOptionalJSON(w, r, &req); err != nil {
			s.writeErr(w, r, err)
			return
		}
		s.rebaseline(w, r, d, who, req.Relearn)
	default:
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown action "+verb, nil)
	}
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request, domain, who string) {
	wt, _, err := s.store.UpdateWatch(r.Context(), domain, who, "watch.confirm",
		func(cur watch.Watch, st diff.State, _ []check.Observation) (store.CheckResult, error) {
			next, err := watch.Confirm(cur, who, s.now())
			return store.CheckResult{Watch: next, Diff: st}, err
		})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wt)
}

func (s *Server) rebaseline(w http.ResponseWriter, r *http.Request, domain, who string, relearn bool) {
	action := "watch.rebaseline"
	if relearn {
		action = "watch.relearn"
	}
	wt, evs, err := s.store.UpdateWatch(r.Context(), domain, who, action,
		func(cur watch.Watch, st diff.State, latest []check.Observation) (store.CheckResult, error) {
			facts, _ := check.Facts(latest, s.extractors)
			out, err := watch.Rebaseline(cur, st, facts, relearn, s.now())
			if err != nil {
				return store.CheckResult{}, err
			}
			routes := make([][]string, len(out.Events))
			if s.route != nil {
				for i, e := range out.Events {
					routes[i] = s.route(e)
				}
			}
			return store.CheckResult{Watch: out.Watch, Diff: out.Diff, Events: out.Events, Routes: routes}, nil
		})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if len(evs) > 0 && s.onEvents != nil {
		s.onEvents()
	}
	writeJSON(w, http.StatusOK, wt)
}

// decodeOptionalJSON is decodeJSON that accepts an empty body.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any) error {
	err := decodeJSON(w, r, maxBodyBytes, v)
	if err != nil && errors.Is(err, errBadRequest) && strings.Contains(err.Error(), io.EOF.Error()) {
		return nil
	}
	return err
}
