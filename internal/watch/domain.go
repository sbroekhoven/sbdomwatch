package watch

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrInvalidDomain is wrapped by every NormalizeDomain error.
var ErrInvalidDomain = errors.New("invalid domain")

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
)

// reservedTLDs are special-use or private top-level names that never resolve
// in the public DNS (RFC 2606, 6761, 6762, 7686, 8375, 9476 and common
// private namespaces).
var reservedTLDs = map[string]bool{
	"alt": true, "arpa": true, "corp": true, "example": true, "home": true,
	"internal": true, "intranet": true, "invalid": true, "lan": true,
	"local": true, "localdomain": true, "localhost": true, "onion": true,
	"private": true, "test": true,
}

// NormalizeDomain returns the canonical form of a domain name: lowercase,
// punycode, without a trailing dot. It rejects IP literals, URLs,
// single-label names, special-use and unknown TLDs, and public suffixes.
func NormalizeDomain(raw string) (string, error) {
	fail := func(format string, a ...any) (string, error) {
		return "", fmt.Errorf("%w %q: %s", ErrInvalidDomain, raw, fmt.Sprintf(format, a...))
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return fail("empty")
	}
	if strings.ContainsAny(s, "/:@ \t[]") {
		return fail("not a bare domain name")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return fail("IP addresses are not allowed")
	}
	s = strings.TrimSuffix(s, ".")
	if strings.HasSuffix(s, ".") {
		return fail("empty label")
	}
	ascii, err := idnaProfile.ToASCII(s)
	if err != nil {
		return fail("%v", err)
	}
	ascii = strings.ToLower(ascii)
	if _, err := netip.ParseAddr(ascii); err == nil {
		return fail("IP addresses are not allowed")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return fail("single-label names are not allowed")
	}
	tld := labels[len(labels)-1]
	if reservedTLDs[tld] {
		return fail("reserved or private TLD .%s", tld)
	}
	if strings.Trim(tld, "0123456789") == "" {
		return fail("numeric TLD")
	}
	suffix, icann := publicsuffix.PublicSuffix(ascii)
	if !icann && !strings.Contains(suffix, ".") {
		return fail("unknown TLD .%s", tld)
	}
	if suffix == ascii {
		return fail("is a public suffix")
	}
	return ascii, nil
}

// DisplayDomain returns the Unicode form of a normalized domain for humans.
func DisplayDomain(ascii string) string {
	u, err := idna.ToUnicode(ascii)
	if err != nil {
		return ascii
	}
	return u
}
