package ratelimit

import (
	"context"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestReserve(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := New(2, 2, c.now) // 2 per second, burst 2

	steps := []struct {
		advance time.Duration
		key     string
		want    time.Duration
	}{
		{0, "a", 0},                      // burst token 1
		{0, "a", 0},                      // burst token 2
		{0, "a", 500 * time.Millisecond}, // empty: wait one interval
		{0, "a", time.Second},            // queued behind the previous one
		{0, "b", 0},                      // other key has its own bucket
		{2 * time.Second, "a", 0},        // refilled
		{0, "a", 0},                      // refill is capped at burst...
		{0, "a", 500 * time.Millisecond}, // ...so the third waits
		{250 * time.Millisecond, "a", 750 * time.Millisecond},
	}
	for i, s := range steps {
		c.t = c.t.Add(s.advance)
		if got := l.reserve(s.key); got != s.want {
			t.Errorf("step %d: reserve(%s) = %v, want %v", i, s.key, got, s.want)
		}
	}
}

func TestWaitHonoursContext(t *testing.T) {
	l := New(0.001, 1, nil)
	if err := l.Wait(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.Wait(ctx, "x"); err == nil {
		t.Fatal("want context error")
	}
	if time.Since(start) > time.Second {
		t.Error("Wait did not return promptly on cancel")
	}
}
