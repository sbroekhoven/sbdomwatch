package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// Request limits.
const (
	maxBodyBytes     = 64 << 10
	maxBulkBodyBytes = 8 << 20
	MaxBulkItems     = 1000
)

// HeaderActor names who performs a change, for added_by and the audit log.
const HeaderActor = "X-Actor"

// Store is what the API needs from the store.
type Store interface {
	AddWatches(ctx context.Context, reqs []watch.AddRequest, actor string, d watch.Defaults) ([]store.AddResult, error)
	GetWatch(ctx context.Context, domain string) (watch.Watch, error)
	ListWatches(ctx context.Context, f store.Filter) ([]watch.Watch, error)
	PatchWatch(ctx context.Context, domain string, p watch.PatchRequest, actor string) (watch.Watch, error)
	ArchiveWatch(ctx context.Context, domain, actor string) (watch.Watch, error)
	DeleteWatch(ctx context.Context, domain, actor string) error
	History(ctx context.Context, domain string, since time.Time, limit int) ([]store.TimelineEntry, error)
	ListEvents(ctx context.Context, f store.EventFilter) ([]events.Event, error)
}

// BulkRequest is the body of POST /v1/watches:bulk.
type BulkRequest struct {
	Watches []watch.AddRequest `json:"watches"`
}

// BulkResponse summarizes a bulk add.
type BulkResponse struct {
	Created   int               `json:"created"`
	Merged    int               `json:"merged"`
	Unchanged int               `json:"unchanged"`
	Results   []store.AddResult `json:"results"`
}

// ListResponse is the body of GET /v1/watches.
type ListResponse struct {
	Watches []watch.Watch `json:"watches"`
}

func (s *Server) routes(mux *http.ServeMux) {
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/watches", s.handleAdd)
	v1.HandleFunc("POST /v1/watches:bulk", s.handleBulk)
	v1.HandleFunc("GET /v1/watches", s.handleList)
	v1.HandleFunc("GET /v1/watches/{domain}", s.handleGet)
	v1.HandleFunc("PATCH /v1/watches/{domain}", s.handlePatch)
	v1.HandleFunc("DELETE /v1/watches/{domain}", s.handleDelete)
	v1.HandleFunc("GET /v1/watches/{domain}/history", s.handleHistory)
	v1.HandleFunc("GET /v1/events", s.handleEvents)
	mux.Handle("/v1/", s.requireToken(v1))
}

func actor(r *http.Request) (string, error) {
	return watch.NormalizeActor(r.Header.Get(HeaderActor))
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	var req watch.AddRequest
	if err := decodeJSON(w, r, maxBodyBytes, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	who, err := actor(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	n, err := req.Normalize()
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	res, err := s.store.AddWatches(r.Context(), []watch.AddRequest{n}, who, s.defaults)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	status := http.StatusOK
	if res[0].Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, res[0])
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	var req BulkRequest
	if err := decodeJSON(w, r, maxBulkBodyBytes, &req); err != nil {
		s.writeErr(w, r, err)
		return
	}
	who, err := actor(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if len(req.Watches) == 0 {
		s.writeErr(w, r, badRequest("watches is empty"))
		return
	}
	if len(req.Watches) > MaxBulkItems {
		s.writeErr(w, r, badRequest("more than %d watches in one request", MaxBulkItems))
		return
	}
	reqs := make([]watch.AddRequest, len(req.Watches))
	var ve watch.ValidationError
	for i, item := range req.Watches {
		n, err := item.Normalize()
		if err != nil {
			var ive *watch.ValidationError
			if !errors.As(err, &ive) {
				s.writeErr(w, r, err)
				return
			}
			for _, f := range ive.Fields {
				f.Field = fmt.Sprintf("watches[%d].%s", i, f.Field)
				ve.Fields = append(ve.Fields, f)
			}
			continue
		}
		reqs[i] = n
	}
	if len(ve.Fields) > 0 {
		s.writeErr(w, r, &ve)
		return
	}
	res, err := s.store.AddWatches(r.Context(), reqs, who, s.defaults)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	out := BulkResponse{Results: res}
	for _, x := range res {
		switch {
		case x.Created:
			out.Created++
		case x.Changed:
			out.Merged++
		default:
			out.Unchanged++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.Filter
	var ve watch.ValidationError
	if v := q.Get("state"); v != "" {
		f.State = watch.State(v)
		if !f.State.Valid() {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "state", Message: "unknown state"})
		}
	}
	if v := q.Get("origin"); v != "" {
		f.Origin = watch.OriginKind(v)
		if !f.Origin.Valid() {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "origin", Message: "unknown origin"})
		}
	}
	if v := q.Get("tag"); v != "" {
		k, val, ok := strings.Cut(v, "=")
		if !ok || watch.ValidateTag(k, val) != nil {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "tag", Message: "want key=value with a valid key"})
		}
		f.TagKey, f.TagVal = k, val
	}
	if v := q.Get("stale"); v != "" {
		stale, err := strconv.ParseBool(v)
		if err != nil {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "stale", Message: "want true or false"})
		}
		if stale {
			f.StaleAt = s.now()
		}
	}
	if v := q.Get("all"); v != "" {
		all, err := strconv.ParseBool(v)
		if err != nil {
			ve.Fields = append(ve.Fields, watch.FieldError{Field: "all", Message: "want true or false"})
		}
		f.All = all
	}
	if len(ve.Fields) > 0 {
		s.writeErr(w, r, &ve)
		return
	}
	ws, err := s.store.ListWatches(r.Context(), f)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if ws == nil {
		ws = []watch.Watch{}
	}
	writeJSON(w, http.StatusOK, ListResponse{Watches: ws})
}

// pathDomain normalizes the {domain} path value.
func pathDomain(r *http.Request) (string, error) {
	d, err := watch.NormalizeDomain(r.PathValue("domain"))
	if err != nil {
		return "", &watch.ValidationError{Fields: []watch.FieldError{{Field: "domain", Message: err.Error()}}}
	}
	return d, nil
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	d, err := pathDomain(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	wt, err := s.store.GetWatch(r.Context(), d)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wt)
}

func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request) {
	d, err := pathDomain(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var p watch.PatchRequest
	if err := decodeJSON(w, r, maxBodyBytes, &p); err != nil {
		s.writeErr(w, r, err)
		return
	}
	who, err := actor(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := p.Validate(); err != nil {
		s.writeErr(w, r, err)
		return
	}
	wt, err := s.store.PatchWatch(r.Context(), d, p, who)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wt)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	d, err := pathDomain(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	who, err := actor(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	hard := false
	if v := r.URL.Query().Get("hard"); v != "" {
		if hard, err = strconv.ParseBool(v); err != nil {
			s.writeErr(w, r, badRequest("hard: want true or false"))
			return
		}
	}
	if hard {
		if err := s.store.DeleteWatch(r.Context(), d, who); err != nil {
			s.writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	wt, err := s.store.ArchiveWatch(r.Context(), d, who)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, wt)
}
