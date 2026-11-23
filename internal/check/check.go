// Package check defines the Check interface that every observation source
// (DNS now, RDAP later) implements.
package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
)

// Check observes one aspect of a domain.
type Check interface {
	// Name is stable and stored with every observation, e.g. "dns".
	Name() string
	// Run observes domain. It returns an error only when nothing useful was
	// observed (for example every resolver failed); partial failures are
	// recorded inside the observation data.
	Run(ctx context.Context, domain string) (Observation, error)
}

// Observation is the result of one check run.
type Observation struct {
	Check      string          `json:"check"`
	ObservedAt time.Time       `json:"observed_at"`
	Data       json.RawMessage `json:"data"` // canonical JSON
	Hash       string          `json:"hash"` // sha256 of Data, hex
}

// NewObservation encodes data as canonical JSON and hashes it. Canonical
// means encoding/json output of a value whose lists are already sorted:
// struct fields keep their order and map keys are sorted by the encoder.
func NewObservation(name string, at time.Time, data any) (Observation, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return Observation{}, fmt.Errorf("check %s: encode observation: %w", name, err)
	}
	sum := sha256.Sum256(b)
	return Observation{Check: name, ObservedAt: at.UTC(), Data: b, Hash: hex.EncodeToString(sum[:])}, nil
}

// Facts extracts and merges the facts of observations with the extractor
// registered for each check. A check without an extractor, or whose data
// cannot be read, contributes nothing: its fields count as unknown. Read
// errors are returned for logging.
func Facts(obs []Observation, extractors map[string]diff.Extractor) (diff.Facts, []error) {
	parts := make([]diff.Facts, 0, len(obs))
	var errs []error
	for _, o := range obs {
		ex, ok := extractors[o.Check]
		if !ok {
			continue
		}
		f, err := ex(o.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", o.Check, err))
			continue
		}
		parts = append(parts, f)
	}
	return diff.Merge(parts...), errs
}
