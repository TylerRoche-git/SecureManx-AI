package policytypes

import "github.com/google/uuid"

// ActionType represents the kind of enforcement action to take in response to a security event.
type ActionType string

const (
	ActionDetectOnly        ActionType = "detect_only"
	ActionIsolate           ActionType = "isolate"
	ActionKillReplace       ActionType = "kill_replace"
	ActionQuarantine        ActionType = "quarantine"
	ActionRevokeCredentials ActionType = "revoke_credentials"
	ActionBlockEgress       ActionType = "block_egress"
	ActionFreezePipeline    ActionType = "freeze_pipeline"
	ActionRequireHuman      ActionType = "require_human"
)

// AuthorityLevel indicates whether an action can be executed automatically
// or requires human approval before proceeding.
type AuthorityLevel string

const (
	AuthorityAuto          AuthorityLevel = "auto"
	AuthorityRequiresHuman AuthorityLevel = "requires_human"
)

// PolicyDecision captures the outcome of evaluating a security event against
// the policy matrix, including the chosen action, authority level, and reasoning.
type PolicyDecision struct {
	Action         ActionType     `json:"action"`
	AuthorityLevel AuthorityLevel `json:"authority_level"`
	Rationale      string         `json:"rationale"`
}

// EnforcementAction represents a concrete enforcement step to be carried out
// against one or more targets in response to a security incident.
type EnforcementAction struct {
	ActionID   uuid.UUID  `json:"action_id"`
	Type       ActionType `json:"type"`
	Targets    []string   `json:"targets"`
	PlaybookID string     `json:"playbook_id"`
	IncidentID uuid.UUID  `json:"incident_id"`
}

// NewEnforcementAction creates a new EnforcementAction with a generated UUID v7,
// the specified action type, incident reference, and target list.
func NewEnforcementAction(actionType ActionType, incidentID uuid.UUID, targets []string) EnforcementAction {
	t := make([]string, len(targets))
	copy(t, targets)
	return EnforcementAction{
		ActionID:   uuid.Must(uuid.NewV7()),
		Type:       actionType,
		Targets:    t,
		IncidentID: incidentID,
	}
}
