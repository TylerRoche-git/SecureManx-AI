package eventschema

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// validSourceTypes is the set of recognized source type values.
var validSourceTypes = map[SourceType]bool{
	SourceRuntime:     true,
	SourceNetwork:     true,
	SourceApplication: true,
	SourceSupplyChain: true,
	SourceIdentity:    true,
}

// validAssetTypes is the set of recognized asset type values.
var validAssetTypes = map[AssetType]bool{
	AssetInference:       true,
	AssetAgentSandbox:    true,
	AssetModelGateway:    true,
	AssetBuildSystem:     true,
	AssetInternalService: true,
	AssetDataStore:       true,
}

// validSeverities is the set of recognized severity values.
var validSeverities = map[Severity]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
}

// ValidateEvent checks that an Event meets all structural and value constraints.
// It returns a joined error containing all validation failures, or nil if the event is valid.
func ValidateEvent(e *Event) error {
	var errs []error

	if e.EventID == uuid.Nil {
		errs = append(errs, fmt.Errorf("event_id must not be zero"))
	}

	if e.Timestamp.IsZero() || e.Timestamp.Equal(time.Time{}) {
		errs = append(errs, fmt.Errorf("timestamp must not be zero"))
	}

	if !validSourceTypes[e.SourceType] {
		errs = append(errs, fmt.Errorf("source_type %q is not a valid SourceType", e.SourceType))
	}

	if !validAssetTypes[e.AssetType] {
		errs = append(errs, fmt.Errorf("asset_type %q is not a valid AssetType", e.AssetType))
	}

	if !validSeverities[e.Severity] {
		errs = append(errs, fmt.Errorf("severity %q is not a valid Severity", e.Severity))
	}

	if e.Confidence < 0 || e.Confidence > 1 {
		errs = append(errs, fmt.Errorf("confidence must be in [0,1], got %f", e.Confidence))
	}

	if e.SignalClass == "" {
		errs = append(errs, fmt.Errorf("signal_class must not be empty"))
	}

	return errors.Join(errs...)
}

// ValidateIncident checks that an Incident meets all structural and value constraints.
// It returns a joined error containing all validation failures, or nil if the incident is valid.
func ValidateIncident(i *Incident) error {
	var errs []error

	if i.IncidentID == uuid.Nil {
		errs = append(errs, fmt.Errorf("incident_id must not be zero"))
	}

	if i.Timestamp.IsZero() || i.Timestamp.Equal(time.Time{}) {
		errs = append(errs, fmt.Errorf("timestamp must not be zero"))
	}

	if len(i.ContributingEvents) == 0 {
		errs = append(errs, fmt.Errorf("contributing_events must not be empty"))
	}

	if i.ConfidenceScore < 0 || i.ConfidenceScore > 1 {
		errs = append(errs, fmt.Errorf("confidence_score must be in [0,1], got %f", i.ConfidenceScore))
	}

	return errors.Join(errs...)
}
