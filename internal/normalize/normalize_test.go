package normalize

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

func TestNormalize_ValidJSON(t *testing.T) {
	e := eventschema.NewEvent()
	e.SourceType = eventschema.SourceRuntime
	e.SourceVendor = eventschema.VendorFalco
	e.AssetID = "pod/test-pod"
	e.AssetType = eventschema.AssetInference
	e.WorkloadID = "wl-001"
	e.IdentityID = "sa:default"
	e.Environment = "staging"
	e.SignalClass = "suspicious-exec"
	e.Severity = eventschema.SeverityHigh
	e.Confidence = 0.85
	e.BlastRadiusHint = eventschema.BlastService

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("failed to marshal test event: %v", err)
	}

	norm := NewNormalizer()
	result, err := norm.Normalize(raw)
	if err != nil {
		t.Fatalf("expected successful normalization, got error: %v", err)
	}

	if result.EventID != e.EventID {
		t.Fatalf("event_id mismatch: got %s, want %s", result.EventID, e.EventID)
	}
	if result.SourceType != eventschema.SourceRuntime {
		t.Fatalf("source_type mismatch: got %q, want %q", result.SourceType, eventschema.SourceRuntime)
	}
	if result.SignalClass != "suspicious-exec" {
		t.Fatalf("signal_class mismatch: got %q, want %q", result.SignalClass, "suspicious-exec")
	}
	if result.Confidence != 0.85 {
		t.Fatalf("confidence mismatch: got %f, want %f", result.Confidence, 0.85)
	}
}

func TestNormalize_InvalidJSON(t *testing.T) {
	norm := NewNormalizer()
	_, err := norm.Normalize([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestNormalize_MissingRequiredFields(t *testing.T) {
	// Create a JSON object that has an event_id and timestamp but is missing
	// required fields like source_type, asset_type, severity, and signal_class.
	partial := struct {
		EventID   uuid.UUID `json:"event_id"`
		Timestamp time.Time `json:"timestamp"`
	}{
		EventID:   uuid.Must(uuid.NewV7()),
		Timestamp: time.Now().UTC(),
	}

	raw, err := json.Marshal(partial)
	if err != nil {
		t.Fatalf("failed to marshal partial event: %v", err)
	}

	norm := NewNormalizer()
	_, err = norm.Normalize(raw)
	if err == nil {
		t.Fatal("expected validation error for missing required fields, got nil")
	}
}
