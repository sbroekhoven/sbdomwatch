package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// Error codes in the JSON error envelope.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnauthenticated = "unauthenticated"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeTooLarge        = "too_large"
	CodeInternal        = "internal"
)

// ErrorBody is the JSON error envelope: {"error": {...}}.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes what went wrong.
type ErrorDetail struct {
	Code    string             `json:"code"`
	Message string             `json:"message"`
	Fields  []watch.FieldError `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string, fields []watch.FieldError) {
	writeJSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: msg, Fields: fields}})
}

// writeErr maps an error to a status code. Unknown errors are logged and
// reported as internal without details.
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *watch.ValidationError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, CodeInvalidArgument, ve.Error(), ve.Fields)
	case errors.As(err, &mbe):
		writeError(w, http.StatusRequestEntityTooLarge, CodeTooLarge, fmt.Sprintf("request body larger than %d bytes", mbe.Limit), nil)
	case errors.Is(err, errBadRequest):
		writeError(w, http.StatusBadRequest, CodeInvalidArgument, err.Error(), nil)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), nil)
	case errors.Is(err, watch.ErrArchived):
		writeError(w, http.StatusConflict, CodeConflict, "watch is archived; add it again to reactivate it", nil)
	default:
		s.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "internal error", nil)
	}
}

var errBadRequest = errors.New("bad request")

func badRequest(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errBadRequest, fmt.Sprintf(format, a...))
}

// decodeJSON reads a size-limited JSON body that must match v exactly.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return badRequest("invalid JSON body: %v", err)
	}
	if dec.More() {
		return badRequest("invalid JSON body: trailing data")
	}
	return nil
}
