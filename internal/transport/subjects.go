// Package transport provides NATS messaging infrastructure for the control plane.
package transport

// NATS subject hierarchy for all inter-component communication.
const (
	SubjectRawEvents          = "security.events.raw"
	SubjectNormalizedEvents   = "security.events.normalized"
	SubjectIncidents          = "security.incidents"
	SubjectEnforcementActions = "security.enforcement.actions"
	SubjectEnforcementResults = "security.enforcement.results"
	SubjectAudit              = "security.audit"
)

// JetStream stream names and their subject filters.
const (
	StreamEvents      = "SECURITY_EVENTS"
	StreamIncidents   = "SECURITY_INCIDENTS"
	StreamEnforcement = "SECURITY_ENFORCEMENT"
	StreamAudit       = "SECURITY_AUDIT"
)

// StreamConfig maps each stream to its subject filter pattern.
var StreamConfig = map[string][]string{
	StreamEvents:      {"security.events.>"},
	StreamIncidents:   {"security.incidents.>"},
	StreamEnforcement: {"security.enforcement.>"},
	StreamAudit:       {"security.audit.>"},
}
