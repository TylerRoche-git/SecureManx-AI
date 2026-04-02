package eventschema

import (
	"time"

	"github.com/google/uuid"
)

// AuditPhase identifies the stage in the security response pipeline where an action occurred.
type AuditPhase string

const (
	PhaseDetection   AuditPhase = "detection"
	PhaseCorrelation AuditPhase = "correlation"
	PhaseDecision    AuditPhase = "decision"
	PhaseEnforcement AuditPhase = "enforcement"
	PhaseRecovery    AuditPhase = "recovery"
)

// AuditActor identifies who or what performed the audited action.
type AuditActor string

const (
	ActorSystem AuditActor = "system"
	ActorAgent  AuditActor = "agent"
	ActorHuman  AuditActor = "human"
)

// AuditInputs captures the data that was fed into a decision or action.
type AuditInputs struct {
	CorrelationScore float64 `json:"correlation_score"`
	AssetCriticality string  `json:"asset_criticality"`
	Confidence       float64 `json:"confidence"`
}

// AuditOutputs captures the results of an audited action.
type AuditOutputs struct {
	Action            string   `json:"action"`
	Targets           []string `json:"targets"`
	Success           bool     `json:"success"`
	RollbackAvailable bool     `json:"rollback_available"`
}

// Reversibility describes whether an action can be undone and how.
type Reversibility struct {
	Reversible         bool   `json:"reversible"`
	RollbackPlaybook   string `json:"rollback_playbook"`
	TTLBeforePermanent string `json:"ttl_before_permanent"`
}

// AuditRecord is an immutable log entry that records every action taken during incident response.
type AuditRecord struct {
	AuditID       uuid.UUID     `json:"audit_id"`
	Timestamp     time.Time     `json:"timestamp"`
	Phase         AuditPhase    `json:"phase"`
	EventIDs      []uuid.UUID   `json:"event_ids"`
	Actor         AuditActor    `json:"actor"`
	ActionTaken   string        `json:"action_taken"`
	PolicyRef     string        `json:"policy_ref"`
	Inputs        AuditInputs   `json:"inputs"`
	Outputs       AuditOutputs  `json:"outputs"`
	Rationale     string        `json:"rationale"`
	EvidenceRefs  []string      `json:"evidence_refs"`
	Reversibility Reversibility `json:"reversibility"`
}

// NewAuditRecord creates a new AuditRecord with a generated UUID v7 and the current UTC timestamp.
func NewAuditRecord(phase AuditPhase, actor AuditActor) AuditRecord {
	return AuditRecord{
		AuditID:      uuid.Must(uuid.NewV7()),
		Timestamp:    time.Now().UTC(),
		Phase:        phase,
		Actor:        actor,
		EventIDs:     make([]uuid.UUID, 0),
		EvidenceRefs: make([]string, 0),
		Outputs: AuditOutputs{
			Targets: make([]string, 0),
		},
	}
}
