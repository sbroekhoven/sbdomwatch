// Package ratelimit provides keyed token-bucket rate limiters for upstream
// services (one bucket per DNS resolver or RDAP registry).
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Keyed is a set of token buckets, one per key, created on first use.
type Keyed struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing rate events per second per key, with bursts
// of up to burst events. now may be nil for time.Now.
func New(rate float64, burst int, now func() time.Time) *Keyed {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &Keyed{rate: rate, burst: float64(burst), now: now, buckets: map[string]*bucket{}}
}

// reserve takes a token for key and returns how long the caller must wait
// before using it.
func (k *Keyed) reserve(key string) time.Duration {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	b, ok := k.buckets[key]
	if !ok {
		b = &bucket{tokens: k.burst, last: now}
		k.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(k.burst, b.tokens+elapsed*k.rate)
		b.last = now
	}
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / k.rate * float64(time.Second))
}

// Wait blocks until an event for key is allowed or ctx is done.
func (k *Keyed) Wait(ctx context.Context, key string) error {
	d := k.reserve(key)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
