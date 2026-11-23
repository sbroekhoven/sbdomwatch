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
	return f, nil
}
