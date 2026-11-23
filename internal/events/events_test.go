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
		{"dns.NS", diff.Added, false, RecordAdded, Medium},
		{"dns.NS", diff.Removed, true, NSChanged, Critical},
		{"rdap.nameservers", diff.Changed, false, NSChanged, High},
		{"rdap.nameservers", diff.Added, false, RecordAdded, Medium},
		{"rdap.registrar", diff.Changed, false, RegistrarChanged, High},
		{"rdap.registrar", diff.Added, false, RecordAdded, Medium},
		{"rdap.status", diff.Changed, false, RecordChanged, Medium},
		{"dns.dangling", diff.Added, true, DanglingCNAME, High},
		{"dns.dangling", diff.Changed, false, DanglingCNAME, Medium},
		{"dns.dangling", diff.Removed, true, RecordRemoved, Medium},
		{"dns.A", diff.Added, false, RecordAdded, Medium},
		{"dns.TXT", diff.Changed, true, RecordChanged, Medium},
		{"dns.CAA", diff.Removed, false, RecordRemoved, Medium},
	}
	for _, tt := range tests {
		typ, sev := ForChange(diff.Change{Path: tt.path, Kind: tt.kind}, tt.owned)
		if tt.path == "" {
			continue
		}
		if typ != tt.wantType || sev != tt.wantSev {
			t.Errorf("%s %s owned=%v = %s %s, want %s %s", tt.path, tt.kind, tt.owned, typ, sev, tt.wantType, tt.wantSev)
		}
	}
}

func TestForChangeRegistration(t *testing.T) {
	reg := diff.Change{Path: PathRegistered, Kind: diff.Changed, Before: []string{"false"}, After: []string{"true"}}
	if typ, sev := ForChange(reg, false); typ != Registered || sev != High {
		t.Errorf("registration = %s %s", typ, sev)
	}
	drop := diff.Change{Path: PathRegistered, Kind: diff.Changed, Before: []string{"true"}, After: []string{"false"}}
	if typ, sev := ForChange(drop, true); typ != Dropped || sev != Medium {
		t.Errorf("drop = %s %s", typ, sev)
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
