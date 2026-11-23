// Package rdap is the RDAP check: registration state, registrar, registry
// nameservers, EPP statuses and dates, looked up with domping's RDAP client.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	dprdap "github.com/sbroekhoven/domping/rdap"
	"golang.org/x/net/publicsuffix"

	"github.com/sbroekhoven/sbdomwatch/internal/check"
	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

// Name is the check name stored with observations.
const Name = "rdap"

// Registration states in Data.State.
const (
	StateRegistered    = "registered"
	StateNotRegistered = "not-registered"
	StateNoService     = "no-rdap" // the TLD has no RDAP service
)

// Data is the observation payload.
type Data struct {
	Domain          string     `json:"domain"` // registrable domain that was looked up
	State           string     `json:"state"`
	Registrar       string     `json:"registrar,omitempty"`
	RegistrarIANAID string     `json:"registrar_iana_id,omitempty"`
	Statuses        []string   `json:"statuses"`
	Nameservers     []string   `json:"nameservers"`
	Registered      *time.Time `json:"registered,omitempty"`
	LastChanged     *time.Time `json:"last_changed,omitempty"`
	Expiry          *time.Time `json:"expiry,omitempty"`
}

// Lookuper is the part of domping's client the check uses.
type Lookuper interface {
	Lookup(ctx context.Context, domain string) dprdap.Result
}

// Check is the RDAP check.
type Check struct {
	client Lookuper
	now    func() time.Time
}

var _ check.Check = (*Check)(nil)

// NewClient returns a domping RDAP client spacing requests to each RDAP
// server (one per registry) to at most perSecPerRegistry.
func NewClient(perSecPerRegistry float64, userAgent string) *dprdap.Client {
	return dprdap.New(dprdap.Options{
		HostInterval: time.Duration(float64(time.Second) / perSecPerRegistry),
		UserAgent:    userAgent,
	})
}

// New returns an RDAP check. now may be nil.
func New(client Lookuper, now func() time.Time) *Check {
	if now == nil {
		now = time.Now
	}
	return &Check{client: client, now: now}
}

// Name implements check.Check.
func (c *Check) Name() string { return Name }

// Run implements check.Check. RDAP describes registrable domains, so a
// subdomain watch looks up its registrable domain. An unknown result (server
// errors, rate limits after retries) is an error: nothing was learned.
func (c *Check) Run(ctx context.Context, domain string) (check.Observation, error) {
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return check.Observation{}, fmt.Errorf("rdap %s: %w", domain, err)
	}
	res := c.client.Lookup(ctx, reg)
	if err := ctx.Err(); err != nil {
		return check.Observation{}, err
	}
	d := Data{Domain: reg, Statuses: []string{}, Nameservers: []string{}}
	switch res.State {
	case dprdap.Registered:
		d.State = StateRegistered
		d.Registrar = res.Registrar
		d.RegistrarIANAID = res.RegistrarIANAID
		d.Statuses = diff.Set(res.Statuses)
		d.Nameservers = diff.Set(res.Nameservers)
		d.Registered, d.LastChanged, d.Expiry = res.Registered, res.LastChanged, res.Expiry
	case dprdap.NotRegistered:
		d.State = StateNotRegistered
	case dprdap.NoService:
		d.State = StateNoService
	default:
		msg := res.Err
		if msg == "" {
			msg = "unknown result"
		}
		return check.Observation{}, fmt.Errorf("rdap %s: %w", reg, errors.New(msg))
	}
	return check.NewObservation(Name, c.now(), d)
}

// Facts turns RDAP data into comparable facts:
//
//	rdap.registered  ["true"] or ["false"]
//	rdap.registrar   ["iana:<id>"], or ["name:<name>"] without an IANA ID
//	rdap.nameservers the registry delegation
//	rdap.status      EPP statuses
//
// Dates are not compared: renewals are routine (expiry warnings are their
// own event). A TLD without RDAP gives no facts.
func Facts(data json.RawMessage) (diff.Facts, error) {
	var d Data
	if err := json.Unmarshal(data, &d); err != nil {
		return diff.Facts{}, fmt.Errorf("rdap facts: %w", err)
	}
	f := diff.Facts{Values: map[string][]string{}}
	switch d.State {
	case StateRegistered:
		f.Exists = true
		if d.Expiry != nil {
			f.Meta = map[string]string{"rdap.expiry": d.Expiry.UTC().Format(time.RFC3339)}
		}
		f.Values["rdap.registered"] = []string{"true"}
		f.Values["rdap.registrar"] = registrarKey(d)
		f.Values["rdap.nameservers"] = diff.Set(d.Nameservers)
		f.Values["rdap.status"] = diff.Set(d.Statuses)
	case StateNotRegistered:
		f.Absent = true
		f.Values["rdap.registered"] = []string{"false"}
		f.Values["rdap.registrar"] = []string{}
		f.Values["rdap.nameservers"] = []string{}
		f.Values["rdap.status"] = []string{}
	}
	return f, nil
}

func registrarKey(d Data) []string {
	switch {
	case d.RegistrarIANAID != "":
		return []string{"iana:" + d.RegistrarIANAID}
	case d.Registrar != "":
		return []string{"name:" + strings.ToLower(strings.Join(strings.Fields(d.Registrar), " "))}
	}
	return []string{}
}
