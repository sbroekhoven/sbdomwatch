package config

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr string
	}{
		{name: "empty", in: "", want: map[string]string{}},
		{
			name: "comments and blanks",
			in:   "# comment\n\nA=1\n  # indented comment\nB = two \n",
			want: map[string]string{"A": "1", "B": "two"},
		},
		{name: "export prefix", in: "export TOKEN=abc\n", want: map[string]string{"TOKEN": "abc"}},
		{name: "double quotes", in: `A="hello # not a comment"`, want: map[string]string{"A": "hello # not a comment"}},
		{name: "single quotes", in: `A='x=y' # trailing comment`, want: map[string]string{"A": "x=y"}},
		{name: "inline comment", in: "A=value # comment\n", want: map[string]string{"A": "value"}},
		{name: "hash inside value", in: "A=https://x/#frag\n", want: map[string]string{"A": "https://x/#frag"}},
		{name: "empty value", in: "A=\n", want: map[string]string{"A": ""}},
		{name: "equals in value", in: "A=b=c\n", want: map[string]string{"A": "b=c"}},
		{name: "later wins", in: "A=1\nA=2\n", want: map[string]string{"A": "2"}},
		{name: "missing equals", in: "A\n", wantErr: "line 1: missing '='"},
		{name: "bad key", in: "1A=x\n", wantErr: "line 1: invalid variable name"},
		{name: "unterminated", in: "A=\"open\n", wantErr: "unterminated quote"},
		{name: "text after quote", in: "A=\"x\"y\n", wantErr: "after closing quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDotenv(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDotenvErrorHidesValue(t *testing.T) {
	_, err := ParseDotenv(strings.NewReader("TOKEN=\"s3cret-value\n"))
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error must not contain the value: %v", err)
	}
}

func TestReadDotenv(t *testing.T) {
	dir := t.TempDir()
	got, err := ReadDotenv(filepath.Join(dir, "missing.env"))
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: got %v, %v; want empty, nil", got, err)
	}
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ReadDotenv(p)
	if err != nil || got["A"] != "1" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestGetenv(t *testing.T) {
	proc := map[string]string{"A": "process", "EMPTY": ""}
	lookup := func(k string) (string, bool) { v, ok := proc[k]; return v, ok }
	get := Getenv(lookup, map[string]string{"A": "file", "B": "file", "EMPTY": "file"})
	tests := []struct{ key, want string }{
		{"A", "process"},
		{"B", "file"},
		{"EMPTY", ""}, // set but empty in the process environment still wins
		{"C", ""},
	}
	for _, tt := range tests {
		if got := get(tt.key); got != tt.want {
			t.Errorf("%s = %q, want %q", tt.key, got, tt.want)
		}
	}
}
