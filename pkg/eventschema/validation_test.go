package eventschema

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// makeValidEvent returns a fully populated Event that passes validation.
func makeValidEvent() Event {
	e := NewEvent()
	e.SourceType = SourceRuntime
	e.SourceVendor = VendorFalco
	e.AssetID = "pod/inference-abc"
	e.AssetType = AssetInference
	e.WorkloadID = "wl-001"
	e.IdentityID = "sa:default"
	e.Environment = "production"
	e.SignalClass = "suspicious-exec"
	e.Severity = SeverityHigh
	e.Confidence = 0.85
	e.BlastRadiusHint = BlastService
	return e
}

func TestValidateEvent_ValidPasses(t *testing.T) {
	e := makeValidEvent()
	if err := ValidateEvent(&e); err != nil {
		t.Fatalf("expected nil error for valid event, got: %v", err)
	}
}

func TestValidateEvent_MissingEventID(t *testing.T) {
	e := makeValidEvent()
	e.EventID = uuid.Nil

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for nil EventID, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "event_id must not be zero") {
		t.Fatalf("expected event_id error, got: %s", got)
	}
}

func TestValidateEvent_ZeroTimestamp(t *testing.T) {
	e := makeValidEvent()
	e.Timestamp = time.Time{}

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for zero timestamp, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "timestamp must not be zero") {
		t.Fatalf("expected timestamp error, got: %s", got)
	}
}

func TestValidateEvent_InvalidSourceType(t *testing.T) {
	e := makeValidEvent()
	e.SourceType = "bogus_source"

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for invalid source_type, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "not a valid SourceType") {
		t.Fatalf("expected source_type error, got: %s", got)
	}
}

func TestValidateEvent_NegativeConfidence(t *testing.T) {
	e := makeValidEvent()
	e.Confidence = -0.5

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for negative confidence, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "confidence must be in [0,1]") {
		t.Fatalf("expected confidence error, got: %s", got)
	}
}

func TestValidateEvent_ConfidenceAboveOne(t *testing.T) {
	e := makeValidEvent()
	e.Confidence = 1.5

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for confidence > 1, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "confidence must be in [0,1]") {
		t.Fatalf("expected confidence error, got: %s", got)
	}
}

func TestValidateEvent_EmptySignalClass(t *testing.T) {
	e := makeValidEvent()
	e.SignalClass = ""

	err := ValidateEvent(&e)
	if err == nil {
		t.Fatal("expected error for empty signal_class, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "signal_class must not be empty") {
		t.Fatalf("expected signal_class error, got: %s", got)
	}
}

func TestValidateIncident_ValidPasses(t *testing.T) {
	ids := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	inc := NewIncident(ids)
	inc.ConfidenceScore = 0.75

	if err := ValidateIncident(&inc); err != nil {
		t.Fatalf("expected nil error for valid incident, got: %v", err)
	}
}

func TestValidateIncident_EmptyContributingEvents(t *testing.T) {
	inc := NewIncident(nil)

	err := ValidateIncident(&inc)
	if err == nil {
		t.Fatal("expected error for empty contributing_events, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "contributing_events must not be empty") {
		t.Fatalf("expected contributing_events error, got: %s", got)
	}
}

func TestValidateIncident_ConfidenceOutOfRange(t *testing.T) {
	ids := []uuid.UUID{uuid.Must(uuid.NewV7())}

	tests := []struct {
		name       string
		confidence float64
	}{
		{"negative", -0.1},
		{"above one", 1.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inc := NewIncident(ids)
			inc.ConfidenceScore = tc.confidence

			err := ValidateIncident(&inc)
			if err == nil {
				t.Fatalf("expected error for confidence %f, got nil", tc.confidence)
			}
			if got := err.Error(); !containsSubstring(got, "confidence_score must be in [0,1]") {
				t.Fatalf("expected confidence_score error, got: %s", got)
			}
		})
	}
}

// containsSubstring is a simple helper to check for substring presence.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
