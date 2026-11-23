package events

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"
)

// OutboxStore is what the dispatcher needs from the store.
type OutboxStore interface {
	DueDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error)
	MarkDelivered(ctx context.Context, eventID int64, sink string, at time.Time) error
	MarkFailed(ctx context.Context, eventID int64, sink, msg string, next time.Time) error
}

// DispatcherConfig configures a Dispatcher. Zero values get defaults.
type DispatcherConfig struct {
	Store       OutboxStore
	Sinks       []Sink
	Log         *slog.Logger
	Tick        time.Duration // poll interval; default 5s
	Batch       int           // deliveries per round; default 50
	Timeout     time.Duration // per delivery; default 15s
	BaseBackoff time.Duration // first retry delay; default 30s, doubled per attempt
	MaxBackoff  time.Duration // default 1h; retries never stop
	Now         func() time.Time
	Rand        func() float64
}

// Dispatcher delivers outbox rows to sinks with retry and backoff. Delivery
// is at least once: an event delivered just before a crash may be sent
// again; receivers deduplicate on the event ID.
type Dispatcher struct {
	cfg   DispatcherConfig
	sinks map[string]Sink
	wake  chan struct{}
}

// NewDispatcher returns a dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.Tick <= 0 {
		cfg.Tick = 5 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 30 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	d := &Dispatcher{cfg: cfg, sinks: map[string]Sink{}, wake: make(chan struct{}, 1)}
	for _, s := range cfg.Sinks {
		d.sinks[s.Name()] = s
	}
	return d
}

// Notify asks for a delivery round soon, for example after new events.
func (d *Dispatcher) Notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run delivers until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) error {
	names := make([]string, 0, len(d.sinks))
	for n := range d.sinks {
		names = append(names, n)
	}
	d.cfg.Log.InfoContext(ctx, "outbox started", "sinks", names)
	t := time.NewTicker(d.cfg.Tick)
	defer t.Stop()
	for {
		n, err := d.RunOnce(ctx)
		if ctx.Err() != nil {
			d.cfg.Log.Info("outbox stopped")
			return nil
		}
		if err != nil {
			d.cfg.Log.ErrorContext(ctx, "outbox round failed", "err", err)
		}
		if n == d.cfg.Batch {
			continue
		}
		select {
		case <-ctx.Done():
			d.cfg.Log.Info("outbox stopped")
			return nil
		case <-t.C:
		case <-d.wake:
		}
	}
}

// RunOnce attempts one batch of due deliveries and returns how many were
// due. After a failure, the rest of that sink's deliveries wait for the
// next round so a down sink is not hammered.
func (d *Dispatcher) RunOnce(ctx context.Context) (int, error) {
	due, err := d.cfg.Store.DueDeliveries(ctx, d.cfg.Now(), d.cfg.Batch)
	if err != nil {
		return 0, err
	}
	down := map[string]bool{}
	for _, dl := range due {
		if down[dl.Sink] {
			continue
		}
		log := d.cfg.Log.With("event_id", dl.Event.ID, "sink", dl.Sink, "type", dl.Event.Type)
		sink, ok := d.sinks[dl.Sink]
		var derr error
		if !ok {
			derr = errors.New("sink is not configured")
		} else {
			dctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
			derr = sink.Deliver(dctx, dl.Event)
			cancel()
		}
		if ctx.Err() != nil {
			return len(due), nil // shutting down; the row stays due
		}
		if derr == nil {
			if err := d.cfg.Store.MarkDelivered(ctx, dl.Event.ID, dl.Sink, d.cfg.Now()); err != nil {
				return len(due), err
			}
			log.DebugContext(ctx, "event delivered")
			continue
		}
		down[dl.Sink] = true
		next := d.cfg.Now().Add(d.backoff(dl.Attempts+1, derr))
		if err := d.cfg.Store.MarkFailed(ctx, dl.Event.ID, dl.Sink, derr.Error(), next); err != nil {
			return len(due), err
		}
		log.WarnContext(ctx, "event delivery failed", "attempt", dl.Attempts+1, "err", derr, "next_attempt_at", next)
	}
	return len(due), nil
}

// backoff is BaseBackoff * 2^(attempt-1), capped at MaxBackoff, +/-10%
// jitter, and at least what the sink asked for with Retry-After.
func (d *Dispatcher) backoff(attempt int, err error) time.Duration {
	b := d.cfg.BaseBackoff
	for i := 1; i < attempt && b < d.cfg.MaxBackoff; i++ {
		b *= 2
	}
	b = min(b, d.cfg.MaxBackoff)
	b = time.Duration(float64(b) * (0.9 + 0.2*d.cfg.Rand()))
	var ra *RetryAfterError
	if errors.As(err, &ra) && ra.After > b {
		b = ra.After
	}
	return b.Truncate(time.Second) + time.Second
}
