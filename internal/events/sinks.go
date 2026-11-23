package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sink delivers events somewhere. Deliver must be safe to retry: delivery
// is at least once, and the event ID identifies duplicates.
type Sink interface {
	Name() string
	// MinSeverity is the least severe event the sink receives.
	MinSeverity() Severity
	Deliver(ctx context.Context, e Event) error
}

// RetryAfterError asks the outbox to wait at least After before retrying.
type RetryAfterError struct {
	After time.Duration
	Err   error
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// Router returns, for an event, the names of the sinks that want it.
func Router(sinks []Sink) func(Event) []string {
	return func(e Event) []string {
		var names []string
		for _, s := range sinks {
			if e.Severity.AtLeast(s.MinSeverity()) {
				names = append(names, s.Name())
			}
		}
		return names
	}
}

// Header names of the generic webhook.
const (
	HeaderEvent     = "X-Sbdomwatch-Event"     // event type
	HeaderDelivery  = "X-Sbdomwatch-Delivery"  // event ID, stable across retries
	HeaderTimestamp = "X-Sbdomwatch-Timestamp" // unix seconds
	HeaderSignature = "X-Sbdomwatch-Signature" // sha256=hex(HMAC-SHA256(secret, timestamp + "." + body))
)

// Webhook posts each event as JSON to a URL, optionally signed.
type Webhook struct {
	url       string
	secret    string
	min       Severity
	client    *http.Client
	userAgent string
	now       func() time.Time
}

// NewWebhook returns the generic webhook sink, named "webhook".
func NewWebhook(u, secret string, min Severity, client *http.Client, userAgent string) *Webhook {
	return &Webhook{url: u, secret: secret, min: min, client: client, userAgent: userAgent, now: time.Now}
}

// Name implements Sink.
func (w *Webhook) Name() string { return "webhook" }

// MinSeverity implements Sink.
func (w *Webhook) MinSeverity() Severity { return w.min }

// Deliver implements Sink.
func (w *Webhook) Deliver(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	h := http.Header{}
	h.Set(HeaderEvent, string(e.Type))
	h.Set(HeaderDelivery, strconv.FormatInt(e.ID, 10))
	if w.secret != "" {
		ts := strconv.FormatInt(w.now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		h.Set(HeaderTimestamp, ts)
		h.Set(HeaderSignature, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return post(ctx, w.client, w.url, w.userAgent, body, h)
}

// Discord posts a short text message per event to a Discord webhook.
type Discord struct {
	url       string
	min       Severity
	client    *http.Client
	userAgent string
}

// NewDiscord returns the Discord sink, named "discord".
func NewDiscord(u string, min Severity, client *http.Client, userAgent string) *Discord {
	return &Discord{url: u, min: min, client: client, userAgent: userAgent}
}

// Name implements Sink.
func (d *Discord) Name() string { return "discord" }

// MinSeverity implements Sink.
func (d *Discord) MinSeverity() Severity { return d.min }

// Deliver implements Sink.
func (d *Discord) Deliver(ctx context.Context, e Event) error {
	msg := struct {
		Username        string `json:"username"`
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"` // never ping anyone, whatever the data says
	}{Username: "sbdomwatch", Content: DiscordText(e)}
	msg.AllowedMentions.Parse = []string{}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	return post(ctx, d.client, d.url, d.userAgent, body, nil)
}

// maxDiscordLen is Discord's limit for message content.
const maxDiscordLen = 2000

// DiscordText renders an event as Discord markdown. Values from DNS and RDAP
// are untrusted: they go into code spans with backticks and newlines removed.
func DiscordText(e Event) string {
	var b strings.Builder
	p := e.Payload
	fmt.Fprintf(&b, "**%s · %s** · `%s` (%s)\n", strings.ToUpper(string(e.Severity)), e.Type, code(p.Domain), p.Template)
	if c := p.Change; c != nil {
		if len(c.Added) > 0 {
			fmt.Fprintf(&b, "%s added: %s\n", c.Path, codeList(c.Added))
		}
		if len(c.Removed) > 0 {
			fmt.Fprintf(&b, "%s removed: %s\n", c.Path, codeList(c.Removed))
		}
	}
	if e.Type == BaselineComplete {
		fmt.Fprintf(&b, "Baseline of %d observation(s), %d fields", p.Observations, len(p.Inventory))
		if len(p.VolatileFields) > 0 {
			fmt.Fprintf(&b, ", volatile: %s", codeList(p.VolatileFields))
		}
		b.WriteString("\n")
	}
	for _, o := range p.Origins {
		ref := ""
		if o.Reference != "" {
			ref = ", " + code(o.Reference)
		}
		fmt.Fprintf(&b, "Watched because: %s (%s%s)\n", code(o.Reason), o.Origin, ref)
	}
	s := strings.TrimSpace(b.String())
	if len(s) > maxDiscordLen {
		s = s[:maxDiscordLen-1] + "…"
	}
	return s
}

func code(s string) string {
	s = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func codeList(vs []string) string {
	parts := make([]string, 0, len(vs))
	for i, v := range vs {
		if i == 10 {
			parts = append(parts, fmt.Sprintf("and %d more", len(vs)-10))
			break
		}
		parts = append(parts, "`"+code(v)+"`")
	}
	return strings.Join(parts, ", ")
}

// post sends body and maps the response to an error. Errors never contain
// the URL: webhook URLs are secrets.
func post(ctx context.Context, client *http.Client, u, userAgent string, body []byte, h http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid webhook URL")
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL
		}
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	err = fmt.Errorf("HTTP %d", resp.StatusCode)
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		if d := retryAfter(resp.Header.Get("Retry-After")); d > 0 {
			return &RetryAfterError{After: d, Err: err}
		}
	}
	return err
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		return time.Duration(f * float64(time.Second))
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}
