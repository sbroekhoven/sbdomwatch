package api

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestHandler(t *testing.T) {
	h := New(":0", discard()).Handler()
	tests := []struct {
		method, path string
		wantStatus   int
		wantBody     string
	}{
		{http.MethodGet, "/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{http.MethodHead, "/healthz", http.StatusOK, ""},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed, ""},
		{http.MethodGet, "/nope", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestServeShutsDownOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := New(ln.Addr().String(), discard())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestRunListenError(t *testing.T) {
	if err := New("256.0.0.1:1", discard()).Run(t.Context()); err == nil {
		t.Fatal("want listen error")
	}
}
