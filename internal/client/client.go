// Package client is the Go client for the sbdomwatch API. The CLI uses it;
// other tools can too.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// ErrNotFound matches API errors with status 404.
var ErrNotFound = errors.New("not found")

// APIError is a non-2xx response.
type APIError struct {
	Status int
	Detail api.ErrorDetail
}

func (e *APIError) Error() string {
	msg := e.Detail.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("api: %s (HTTP %d)", msg, e.Status)
}

// Is makes errors.Is(err, ErrNotFound) work for 404 responses.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// Client talks to one sbdomwatch server.
type Client struct {
	base  *url.URL
	token string
	actor string
	http  *http.Client
}

// New returns a client for baseURL. actor is sent as X-Actor. hc may be nil.
func New(baseURL, token, actor string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("client: invalid API URL %q: want http(s)://host[:port]", baseURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: u, token: token, actor: actor, http: hc}, nil
}

// AddWatch adds or merges one watch.
func (c *Client) AddWatch(ctx context.Context, req watch.AddRequest) (store.AddResult, error) {
	var out store.AddResult
	err := c.do(ctx, http.MethodPost, "/v1/watches", nil, req, &out)
	return out, err
}

// BulkAdd adds or merges up to api.MaxBulkItems watches atomically.
func (c *Client) BulkAdd(ctx context.Context, reqs []watch.AddRequest) (api.BulkResponse, error) {
	var out api.BulkResponse
	err := c.do(ctx, http.MethodPost, "/v1/watches:bulk", nil, api.BulkRequest{Watches: reqs}, &out)
	return out, err
}

// ListOptions filter ListWatches.
type ListOptions struct {
	State  watch.State
	Tag    string // key=value
	Origin watch.OriginKind
	All    bool
	Stale  bool // only watches not observed for twice their interval
}

// ListWatches lists watches.
func (c *Client) ListWatches(ctx context.Context, o ListOptions) ([]watch.Watch, error) {
	q := url.Values{}
	if o.State != "" {
		q.Set("state", string(o.State))
	}
	if o.Tag != "" {
		q.Set("tag", o.Tag)
	}
	if o.Origin != "" {
		q.Set("origin", string(o.Origin))
	}
	if o.All {
		q.Set("all", "true")
	}
	if o.Stale {
		q.Set("stale", "true")
	}
	var out api.ListResponse
	err := c.do(ctx, http.MethodGet, "/v1/watches", q, nil, &out)
	return out.Watches, err
}

// GetWatch returns one watch.
func (c *Client) GetWatch(ctx context.Context, domain string) (watch.Watch, error) {
	var out watch.Watch
	err := c.do(ctx, http.MethodGet, watchPath(domain), nil, nil, &out)
	return out, err
}

// PatchWatch changes a watch.
func (c *Client) PatchWatch(ctx context.Context, domain string, p watch.PatchRequest) (watch.Watch, error) {
	var out watch.Watch
	err := c.do(ctx, http.MethodPatch, watchPath(domain), nil, p, &out)
	return out, err
}

// ArchiveWatch archives a watch.
func (c *Client) ArchiveWatch(ctx context.Context, domain string) (watch.Watch, error) {
	var out watch.Watch
	err := c.do(ctx, http.MethodDelete, watchPath(domain), nil, nil, &out)
	return out, err
}

// History returns observations and events of a watch, newest first. since
// is passed through: an RFC 3339 time, a duration like 24h or days like 7d.
func (c *Client) History(ctx context.Context, domain, since string, limit int) (api.HistoryResponse, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out api.HistoryResponse
	err := c.do(ctx, http.MethodGet, watchPath(domain)+"/history", q, nil, &out)
	return out, err
}

// EventOptions filter Events.
type EventOptions struct {
	Since    string   // RFC 3339, 24h or 7d
	Types    []string // event types
	Domain   string
	Severity string // minimum severity
	Limit    int
}

// Events lists events, newest first.
func (c *Client) Events(ctx context.Context, o EventOptions) ([]events.Event, error) {
	q := url.Values{}
	if o.Since != "" {
		q.Set("since", o.Since)
	}
	if len(o.Types) > 0 {
		q.Set("type", strings.Join(o.Types, ","))
	}
	if o.Domain != "" {
		q.Set("watch", o.Domain)
	}
	if o.Severity != "" {
		q.Set("severity", o.Severity)
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	var out api.EventsResponse
	err := c.do(ctx, http.MethodGet, "/v1/events", q, nil, &out)
	return out.Events, err
}

// watchPath is unescaped; do escapes it. A "/" in domain cannot form a
// valid name, so the server rejects it either way.
func watchPath(domain string) string { return "/v1/watches/" + domain }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.base.JoinPath(path) // escapes each segment
	u.RawQuery = q.Encode()

	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("client: encode request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.actor != "" {
		req.Header.Set(api.HeaderActor, c.actor)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("client: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var eb api.ErrorBody
		if json.Unmarshal(data, &eb) == nil {
			apiErr.Detail = eb.Error
		}
		return apiErr
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("client: decode response: %w", err)
	}
	return nil
}
