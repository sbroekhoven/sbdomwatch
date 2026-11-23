// Package dns is the DNS check: it queries A, AAAA, CNAME, MX, NS, TXT, CAA
// and SOA for a domain through recursive resolvers.
package dns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/ratelimit"
)

// Name is the check name stored with observations.
const Name = "dns"

// Types are the record types observed, in this order.
var Types = []uint16{
	mdns.TypeA, mdns.TypeAAAA, mdns.TypeCNAME, mdns.TypeMX,
	mdns.TypeNS, mdns.TypeTXT, mdns.TypeCAA, mdns.TypeSOA,
}

// TypeName returns the mnemonic of a record type, e.g. "MX".
func TypeName(t uint16) string { return mdns.TypeToString[t] }

// Data is the observation payload.
type Data struct {
	Records map[string]RRSet `json:"records"` // keyed by type, e.g. "MX"
}

// RRSet is the answer for one record type.
type RRSet struct {
	Rcode  string  `json:"rcode,omitempty"` // NOERROR, NXDOMAIN, ...; empty when every resolver failed
	Values []Value `json:"values"`          // sorted by value, no duplicates
	Error  string  `json:"error,omitempty"` // set when every resolver failed
}

// Value is one record in presentation form without owner and type.
type Value struct {
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// Config configures the DNS check.
type Config struct {
	Resolvers []string // host:port, tried in order
	Timeout   time.Duration
	Limiter   *ratelimit.Keyed // keyed by resolver; nil disables limiting
	Now       func() time.Time
}

// Check is the DNS check.
type Check struct {
	cfg Config
	udp *mdns.Client
	tcp *mdns.Client
}

var _ check.Check = (*Check)(nil)

// New returns a DNS check.
func New(cfg Config) *Check {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Check{
		cfg: cfg,
		udp: &mdns.Client{Net: "udp", Timeout: cfg.Timeout},
		tcp: &mdns.Client{Net: "tcp", Timeout: cfg.Timeout},
	}
}

// Name implements check.Check.
func (c *Check) Name() string { return Name }

// Run implements check.Check. It fails only when no record type could be
// resolved at all.
func (c *Check) Run(ctx context.Context, domain string) (check.Observation, error) {
	data := Data{Records: make(map[string]RRSet, len(Types))}
	var errs []error
	for _, qt := range Types {
		set, err := c.query(ctx, domain, qt)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return check.Observation{}, ctxErr
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", mdns.TypeToString[qt], err))
			set = RRSet{Values: []Value{}, Error: err.Error()}
		}
		data.Records[mdns.TypeToString[qt]] = set
	}
	if len(errs) == len(Types) {
		return check.Observation{}, fmt.Errorf("dns %s: every query failed: %w", domain, errors.Join(errs...))
	}
	return check.NewObservation(Name, c.cfg.Now(), data)
}

// query asks each resolver in turn until one gives a usable answer.
func (c *Check) query(ctx context.Context, domain string, qt uint16) (RRSet, error) {
	if len(c.cfg.Resolvers) == 0 {
		return RRSet{}, errors.New("no resolvers configured")
	}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), qt)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	var lastErr error
	for _, server := range c.cfg.Resolvers {
		resp, err := c.exchange(ctx, m, server)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			if ctx.Err() != nil {
				return RRSet{}, lastErr
			}
			continue
		}
		if resp.Rcode == mdns.RcodeServerFailure || resp.Rcode == mdns.RcodeRefused {
			lastErr = fmt.Errorf("%s: %s", server, mdns.RcodeToString[resp.Rcode])
			continue
		}
		return RRSet{Rcode: mdns.RcodeToString[resp.Rcode], Values: values(resp.Answer, qt)}, nil
	}
	return RRSet{}, lastErr
}

func (c *Check) exchange(ctx context.Context, m *mdns.Msg, server string) (*mdns.Msg, error) {
	if c.cfg.Limiter != nil {
		if err := c.cfg.Limiter.Wait(ctx, server); err != nil {
			return nil, err
		}
	}
	resp, _, err := c.udp.ExchangeContext(ctx, m, server)
	if err == nil && resp.Truncated {
		resp, _, err = c.tcp.ExchangeContext(ctx, m, server)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// values keeps the records of type qt (a CNAME chain also returns the CNAME
// for an A query) in a stable presentation form.
func values(rrs []mdns.RR, qt uint16) []Value {
	seen := map[string]bool{}
	out := []Value{}
	for _, rr := range rrs {
		if rr.Header().Rrtype != qt {
			continue
		}
		v := present(rr)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, Value{Value: v, TTL: rr.Header().Ttl})
	}
	slices.SortFunc(out, func(a, b Value) int { return strings.Compare(a.Value, b.Value) })
	return out
}

func name(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func present(rr mdns.RR) string {
	switch r := rr.(type) {
	case *mdns.A:
		return r.A.String()
	case *mdns.AAAA:
		return r.AAAA.String()
	case *mdns.CNAME:
		return name(r.Target)
	case *mdns.MX:
		return fmt.Sprintf("%d %s", r.Preference, name(r.Mx))
	case *mdns.NS:
		return name(r.Ns)
	case *mdns.TXT:
		return strings.Join(r.Txt, "")
	case *mdns.CAA:
		return fmt.Sprintf("%d %s %q", r.Flag, strings.ToLower(r.Tag), r.Value)
	case *mdns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", name(r.Ns), name(r.Mbox), r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
	}
	return ""
}
