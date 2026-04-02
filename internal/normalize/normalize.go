// Package normalize provides a simple JSON-based normalizer that deserialises
// raw event bytes into the canonical Event type and validates the result.
package normalize

import (
	"encoding/json"
	"fmt"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// Normalizer parses raw JSON into an eventschema.Event and validates it.
// It satisfies the ingest.Normalizer interface.
type Normalizer struct{}

// NewNormalizer returns a ready-to-use Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize unmarshals raw JSON bytes into an Event, validates the result,
// and returns the populated Event or an error describing what went wrong.
func (n *Normalizer) Normalize(raw []byte) (*eventschema.Event, error) {
	var event eventschema.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("unmarshal event: %w", err)
	}

	if err := eventschema.ValidateEvent(&event); err != nil {
		return nil, fmt.Errorf("validate event: %w", err)
	}

	return &event, nil
}
