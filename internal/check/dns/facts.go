package dns

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

// Facts turns DNS observation data into comparable facts, one path per
// record type ("dns.MX"). TTLs are dropped. A type whose lookup failed is
// left out (unknown). NXDOMAIN gives an empty set. For SOA only the primary
// nameserver and the contact are kept: the serial and timers change all
// the time without meaning anything. The domain is absent when every type
// answered NXDOMAIN.
func Facts(data json.RawMessage) (diff.Facts, error) {
	var d Data
	if err := json.Unmarshal(data, &d); err != nil {
		return diff.Facts{}, fmt.Errorf("dns facts: %w", err)
	}
	f := diff.Facts{Values: map[string][]string{}}
	nx, known := 0, 0
	for typ, set := range d.Records {
		if set.Error != "" || set.Rcode == "" {
			continue
		}
		known++
		if set.Rcode == "NXDOMAIN" {
			nx++
			f.Values["dns."+typ] = []string{}
			continue
		}
		if set.Rcode != "NOERROR" {
			continue // other rcodes say nothing reliable about the records
		}
		vals := make([]string, 0, len(set.Values))
		for _, v := range set.Values {
			s := v.Value
			if typ == "SOA" {
				if fields := strings.Fields(s); len(fields) >= 2 {
					s = fields[0] + " " + fields[1]
				}
			}
			vals = append(vals, s)
		}
		f.Values["dns."+typ] = diff.Set(vals)
	}
	f.Absent = known > 0 && nx == known && known == len(d.Records)
	if v, ok := dangling(d); ok {
		f.Values["dns.dangling"] = v
	}
	return f, nil
}

// dangling reports the CNAME target when the name has a CNAME whose target
// does not exist: A and AAAA (which follow the CNAME) both answer NXDOMAIN.
// The result is unknown (ok false) when any of the three lookups failed.
func dangling(d Data) (values []string, ok bool) {
	cname, okC := d.Records["CNAME"]
	a, okA := d.Records["A"]
	aaaa, okAAAA := d.Records["AAAA"]
	if !okC || cname.Error != "" || cname.Rcode == "" {
		return nil, false
	}
	if cname.Rcode != "NOERROR" || len(cname.Values) == 0 {
		return []string{}, true
	}
	if !okA || !okAAAA || a.Error != "" || aaaa.Error != "" || a.Rcode == "" || aaaa.Rcode == "" {
		return nil, false
	}
	if a.Rcode == "NXDOMAIN" && aaaa.Rcode == "NXDOMAIN" {
		return []string{cname.Values[0].Value}, true
	}
	return []string{}, true
}
