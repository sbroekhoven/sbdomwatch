package main

import (
	"encoding/json"
	"io"
	"text/tabwriter"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// displayDomain shows the punycode name with its Unicode form when they differ.
func displayDomain(ascii string) string {
	if u := watch.DisplayDomain(ascii); u != ascii {
		return ascii + " (" + u + ")"
	}
	return ascii
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return formatTime(*t)
}
