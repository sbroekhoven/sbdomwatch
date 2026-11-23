package watch

import (
	"errors"
	"strings"
	"testing"
)

func TestAddRequestNormalize(t *testing.T) {
	valid := AddRequest{Domain: "Degiro.NL.", Template: TemplateOwned, Reason: "  company domain  "}
	tests := []struct {
		name      string
		mutate    func(r *AddRequest)
		wantField string // empty: valid
		check     func(t *testing.T, r AddRequest)
	}{
		{
			name: "valid is normalized",
			check: func(t *testing.T, r AddRequest) {
				if r.Domain != "degiro.nl" || r.Reason != "company domain" || r.Origin != OriginManual {
					t.Errorf("got %+v", r)
				}
			},
		},
		{name: "empty reason", mutate: func(r *AddRequest) { r.Reason = "" }, wantField: "reason"},
		{name: "blank reason", mutate: func(r *AddRequest) { r.Reason = " \t " }, wantField: "reason"},
		{name: "long reason", mutate: func(r *AddRequest) { r.Reason = strings.Repeat("x", MaxReasonLen+1) }, wantField: "reason"},
		{name: "control in reason", mutate: func(r *AddRequest) { r.Reason = "a\x00b" }, wantField: "reason"},
		{name: "bad domain", mutate: func(r *AddRequest) { r.Domain = "1.2.3.4" }, wantField: "domain"},
		{name: "bad template", mutate: func(r *AddRequest) { r.Template = "mine" }, wantField: "template"},
		{name: "missing template", mutate: func(r *AddRequest) { r.Template = "" }, wantField: "template"},
		{name: "bad origin", mutate: func(r *AddRequest) { r.Origin = "feed" }, wantField: "origin"},
		{name: "typosquat origin", mutate: func(r *AddRequest) { r.Origin = OriginTyposquat }},
		{name: "interval too short", mutate: func(r *AddRequest) { r.IntervalSec = 10 }, wantField: "interval_sec"},
		{name: "interval ok", mutate: func(r *AddRequest) { r.IntervalSec = 3600 }},
		{name: "bad tag key", mutate: func(r *AddRequest) { r.Tags = map[string]string{"Bad Key": "x"} }, wantField: "tags.Bad Key"},
		{name: "good tag", mutate: func(r *AddRequest) { r.Tags = map[string]string{"profile": "degiro"} }},
		{name: "long reference", mutate: func(r *AddRequest) { r.Reference = strings.Repeat("r", MaxReferenceLen+1) }, wantField: "reference"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid
			if tt.mutate != nil {
				tt.mutate(&r)
			}
			got, err := r.Normalize()
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.check != nil {
					tt.check(t, got)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v, want ValidationError", err)
			}
			found := false
			for _, f := range ve.Fields {
				found = found || f.Field == tt.wantField
			}
			if !found {
				t.Errorf("fields = %+v, want %q", ve.Fields, tt.wantField)
			}
		})
	}
}

func TestNormalizeActor(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"", "api", false},
		{"seb", "seb", false},
		{"sbsquat@host-1", "sbsquat@host-1", false},
		{"seb broekhoven", "", true},
		{"<script>", "", true},
		{strings.Repeat("a", 65), "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeActor(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeActor(%q) = %q, %v", tt.in, got, err)
		}
	}
}

func TestPatchValidate(t *testing.T) {
	short, ok := 5, 600
	if err := (PatchRequest{IntervalSec: &short}).Validate(); err == nil {
		t.Error("want error for short interval")
	}
	if err := (PatchRequest{IntervalSec: &ok, Tags: map[string]*string{"a": nil}}).Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := (PatchRequest{Tags: map[string]*string{"A B": nil}}).Validate(); err == nil {
		t.Error("want error for bad tag key")
	}
}
