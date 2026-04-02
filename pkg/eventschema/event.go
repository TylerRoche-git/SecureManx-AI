package eventschema

import (
	"time"

	"github.com/google/uuid"
)

// SourceType classifies the origin category of a security event.
type SourceType string

const (
	SourceRuntime     SourceType = "runtime"
	SourceNetwork     SourceType = "network"
	SourceApplication SourceType = "application"
	SourceSupplyChain SourceType = "supply_chain"
	SourceIdentity    SourceType = "identity"
)

// SourceVendor identifies the tool or system that produced the event.
type SourceVendor string

const (
	VendorFalco    SourceVendor = "falco"
	VendorHubble   SourceVendor = "hubble"
	VendorCIScanner SourceVendor = "ci_scanner"
	VendorGateway  SourceVendor = "gateway"
	VendorK8sAudit SourceVendor = "k8s_audit"
)

// AssetType classifies the kind of infrastructure asset involved in an event.
type AssetType string

const (
	AssetInference       AssetType = "inference"
	AssetAgentSandbox    AssetType = "agent_sandbox"
	AssetModelGateway    AssetType = "model_gateway"
	AssetBuildSystem     AssetType = "build_system"
	AssetInternalService AssetType = "internal_service"
	AssetDataStore       AssetType = "data_store"
)

// Severity represents the impact level of a security event.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// BlastRadius estimates the scope of potential impact from a security event.
type BlastRadius string

const (
	BlastIsolated  BlastRadius = "isolated"
	BlastService   BlastRadius = "service"
	BlastNamespace BlastRadius = "namespace"
	BlastCluster   BlastRadius = "cluster"
)

// Event represents a normalized security event from any detection source.
type Event struct {
	EventID          uuid.UUID      `json:"event_id"`
	Timestamp        time.Time      `json:"timestamp"`
	SourceType       SourceType     `json:"source_type"`
	SourceVendor     SourceVendor   `json:"source_vendor"`
	AssetID          string         `json:"asset_id"`
	AssetType        AssetType      `json:"asset_type"`
	WorkloadID       string         `json:"workload_id"`
	IdentityID       string         `json:"identity_id"`
	Environment      string         `json:"environment"`
	SignalClass      string         `json:"signal_class"`
	Severity         Severity       `json:"severity"`
	Confidence       float64        `json:"confidence"`
	Observables      map[string]any `json:"observables"`
	EvidenceRefs     []string       `json:"evidence_refs"`
	SuggestedActions []string       `json:"suggested_actions"`
	BlastRadiusHint  BlastRadius    `json:"blast_radius_hint"`
}

// NewEvent creates a new Event with a generated UUID v7 and the current UTC timestamp.
func NewEvent() Event {
	return Event{
		EventID:          uuid.Must(uuid.NewV7()),
		Timestamp:        time.Now().UTC(),
		Observables:      make(map[string]any),
		EvidenceRefs:     make([]string, 0),
		SuggestedActions: make([]string, 0),
	}
}
