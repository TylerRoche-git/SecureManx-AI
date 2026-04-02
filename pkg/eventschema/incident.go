package eventschema

import (
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// ExecutionStatus tracks the lifecycle state of an incident response action.
type ExecutionStatus string

const (
	StatusPending    ExecutionStatus = "pending"
	StatusExecuting  ExecutionStatus = "executing"
	StatusCompleted  ExecutionStatus = "completed"
	StatusFailed     ExecutionStatus = "failed"
	StatusRolledBack ExecutionStatus = "rolled_back"
)

// Incident represents a correlated security incident derived from one or more events.
type Incident struct {
	IncidentID          uuid.UUID                  `json:"incident_id"`
	Timestamp           time.Time                  `json:"timestamp"`
	ContributingEvents  []uuid.UUID                `json:"contributing_events"`
	ThreatHypothesis    string                     `json:"threat_hypothesis"`
	ConfidenceScore     float64                    `json:"confidence_score"`
	AssetCriticality    Severity                   `json:"asset_criticality"`
	RecommendedPlaybook string                     `json:"recommended_playbook"`
	PolicyDecision      policytypes.PolicyDecision `json:"policy_decision"`
	ExecutionStatus     ExecutionStatus            `json:"execution_status"`
}

// NewIncident creates a new Incident with a generated UUID v7 and the current UTC timestamp.
// The provided contributing event IDs are copied into the incident.
func NewIncident(contributingEvents []uuid.UUID) Incident {
	events := make([]uuid.UUID, len(contributingEvents))
	copy(events, contributingEvents)

	return Incident{
		IncidentID:         uuid.Must(uuid.NewV7()),
		Timestamp:          time.Now().UTC(),
		ContributingEvents: events,
		ExecutionStatus:    StatusPending,
	}
}
