package watch

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "Degiro.NL.", want: "degiro.nl"},
		{in: "  example.com  ", want: "example.com"},
		{in: "bücher.de", want: "xn--bcher-kva.de"},
		{in: "BÜCHER.de", want: "xn--bcher-kva.de"},
		{in: "xn--bcher-kva.de", want: "xn--bcher-kva.de"},
		{in: "mail.example.co.uk", want: "mail.example.co.uk"},
		{in: "例え.jp", want: "xn--r8jz45g.jp"},
		{in: "foo.blogspot.com", want: "foo.blogspot.com"},
		{in: "", wantErr: "empty"},
		{in: "   ", wantErr: "empty"},
		{in: "localhost", wantErr: "single-label"},
		{in: "com", wantErr: "single-label"},
		{in: "printer.local", wantErr: "reserved"},
		{in: "foo.internal", wantErr: "reserved"},
		{in: "router.home.arpa", wantErr: "reserved"},
		{in: "x.onion", wantErr: "reserved"},
		{in: "foo.notarealtld", wantErr: "unknown TLD"},
		{in: "co.uk", wantErr: "public suffix"},
		{in: "blogspot.com", wantErr: "public suffix"},
		{in: "1.2.3.4", wantErr: "IP"},
		{in: "::1", wantErr: "not a bare domain"},
		{in: "[2001:db8::1]", wantErr: "not a bare domain"},
		{in: "10.0.0.1.", wantErr: "IP"},
		{in: "https://example.com", wantErr: "not a bare domain"},
		{in: "example.com/path", wantErr: "not a bare domain"},
		{in: "user@example.com", wantErr: "not a bare domain"},
		{in: "example.com:443", wantErr: "not a bare domain"},
		{in: "exa mple.com", wantErr: "not a bare domain"},
		{in: "example..com", wantErr: "invalid domain"},
		{in: "example.com..", wantErr: "empty label"},
		{in: "-bad.com", wantErr: "invalid domain"},
		{in: "under_score.com", wantErr: "invalid domain"},
		{in: strings.Repeat("a", 64) + ".com", wantErr: "invalid domain"},
		{in: "foo.123", wantErr: "numeric TLD"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeDomain(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NormalizeDomain(%q) = %q, %v; want error containing %q", tt.in, got, err, tt.wantErr)
				}
				if !errors.Is(err, ErrInvalidDomain) {
					t.Errorf("error does not wrap ErrInvalidDomain: %v", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestDisplayDomain(t *testing.T) {
	if got := DisplayDomain("xn--bcher-kva.de"); got != "bücher.de" {
		t.Errorf("got %q", got)
	}
}
