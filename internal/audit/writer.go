package audit

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// Writer provides high-level methods for recording audit entries at each stage
// of the incident response pipeline.
type Writer struct {
	store *Store
}

// NewWriter creates a Writer backed by the given audit Store.
func NewWriter(store *Store) *Writer {
	return &Writer{store: store}
}

// RecordDetection creates an audit record for the detection phase, capturing
// the originating event ID and signal class.
func (w *Writer) RecordDetection(ctx context.Context, event *eventschema.Event) error {
	rec := eventschema.NewAuditRecord(eventschema.PhaseDetection, eventschema.ActorSystem)
	rec.EventIDs = []uuid.UUID{event.EventID}
	rec.ActionTaken = event.SignalClass
	rec.Inputs = eventschema.AuditInputs{
		Confidence: event.Confidence,
	}
	rec.EvidenceRefs = event.EvidenceRefs
	if rec.EvidenceRefs == nil {
		rec.EvidenceRefs = make([]string, 0)
	}

	if err := w.store.Insert(ctx, &rec); err != nil {
		return fmt.Errorf("record detection: %w", err)
	}
	return nil
}

// RecordCorrelation creates an audit record for the correlation phase,
// capturing the contributing event IDs and threat hypothesis.
func (w *Writer) RecordCorrelation(ctx context.Context, incident *eventschema.Incident) error {
	rec := eventschema.NewAuditRecord(eventschema.PhaseCorrelation, eventschema.ActorAgent)
	rec.EventIDs = make([]uuid.UUID, len(incident.ContributingEvents))
	copy(rec.EventIDs, incident.ContributingEvents)
	rec.ActionTaken = incident.ThreatHypothesis
	rec.Inputs = eventschema.AuditInputs{
		Confidence:       incident.ConfidenceScore,
		AssetCriticality: string(incident.AssetCriticality),
	}
	rec.Rationale = incident.ThreatHypothesis

	if err := w.store.Insert(ctx, &rec); err != nil {
		return fmt.Errorf("record correlation: %w", err)
	}
	return nil
}

// RecordDecision creates an audit record for the decision phase, capturing the
// policy evaluation inputs (confidence and criticality) and the chosen action.
func (w *Writer) RecordDecision(ctx context.Context, incident *eventschema.Incident, decision *policytypes.PolicyDecision) error {
	rec := eventschema.NewAuditRecord(eventschema.PhaseDecision, eventschema.ActorAgent)
	rec.EventIDs = make([]uuid.UUID, len(incident.ContributingEvents))
	copy(rec.EventIDs, incident.ContributingEvents)
	rec.Inputs = eventschema.AuditInputs{
		Confidence:       incident.ConfidenceScore,
		AssetCriticality: string(incident.AssetCriticality),
	}
	rec.Outputs = eventschema.AuditOutputs{
		Action:  string(decision.Action),
		Targets: make([]string, 0),
	}
	rec.Rationale = decision.Rationale
	rec.PolicyRef = string(decision.AuthorityLevel)

	if err := w.store.Insert(ctx, &rec); err != nil {
		return fmt.Errorf("record decision: %w", err)
	}
	return nil
}

// RecordEnforcement creates an audit record for the enforcement phase,
// capturing the action taken, its targets, and whether execution succeeded.
func (w *Writer) RecordEnforcement(ctx context.Context, actionID uuid.UUID, action policytypes.ActionType, targets []string, success bool) error {
	rec := eventschema.NewAuditRecord(eventschema.PhaseEnforcement, eventschema.ActorSystem)
	rec.ActionTaken = string(action)
	rec.Outputs = eventschema.AuditOutputs{
		Action:  string(action),
		Targets: make([]string, len(targets)),
		Success: success,
	}
	copy(rec.Outputs.Targets, targets)
	rec.EvidenceRefs = []string{actionID.String()}

	if err := w.store.Insert(ctx, &rec); err != nil {
		return fmt.Errorf("record enforcement: %w", err)
	}
	return nil
}
