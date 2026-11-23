package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireToken rejects requests without the bearer token. Both sides are
// hashed first so the comparison takes the same time whatever the length.
func (s *Server) requireToken(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(s.token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := bearer(r.Header.Get("Authorization"))
		gotSum := sha256.Sum256([]byte(got))
		if !ok || s.token == "" || subtle.ConstantTimeCompare(gotSum[:], want[:]) != 1 {
			s.log.WarnContext(r.Context(), "unauthenticated request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="sbdomwatch"`)
			writeError(w, http.StatusUnauthorized, CodeUnauthenticated, "missing or invalid bearer token", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(h string) (string, bool) {
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
