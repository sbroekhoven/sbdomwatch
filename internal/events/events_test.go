package events

import (
	"testing"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

func TestForChange(t *testing.T) {
	tests := []struct {
		path     string
		kind     diff.ChangeKind
		owned    bool
		wantType Type
		wantSev  Severity
	}{
		{"dns.MX", diff.Added, false, MXAppeared, High},
		{"dns.MX", diff.Changed, false, RecordChanged, Medium},
		{"dns.MX", diff.Removed, false, RecordRemoved, Medium},
		{"dns.NS", diff.Changed, false, NSChanged, High},
		{"dns.NS", diff.Changed, true, NSChanged, Critical},
		{"dns.NS", diff.Added, false, NSChanged, High},
		{"dns.A", diff.Added, false, RecordAdded, Medium},
		{"dns.TXT", diff.Changed, true, RecordChanged, Medium},
		{"dns.CAA", diff.Removed, false, RecordRemoved, Medium},
	}
	for _, tt := range tests {
		typ, sev := ForChange(diff.Change{Path: tt.path, Kind: tt.kind}, tt.owned)
		if typ != tt.wantType || sev != tt.wantSev {
			t.Errorf("%s %s owned=%v = %s %s, want %s %s", tt.path, tt.kind, tt.owned, typ, sev, tt.wantType, tt.wantSev)
		}
	}
}

func TestSeverity(t *testing.T) {
	if !High.AtLeast(Medium) || Medium.AtLeast(High) || !Critical.AtLeast(Critical) || Severity("bogus").Valid() {
		t.Error("severity ordering wrong")
	}
	if got := AtLeast(High); len(got) != 2 || got[0] != High || got[1] != Critical {
		t.Errorf("AtLeast(high) = %v", got)
	}
	if !ValidType(MXAppeared) || ValidType("nope") {
		t.Error("ValidType wrong")
	}
}
