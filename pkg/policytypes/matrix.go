package policytypes

// ConfidenceBand categorises a numeric confidence score into discrete bands
// used to select the appropriate response actions from the policy matrix.
type ConfidenceBand int

const (
	BandLow      ConfidenceBand = iota // < 0.3
	BandMedium                         // 0.3 – 0.7
	BandHigh                           // 0.7 – 0.9
	BandCritical                       // > 0.9
)

// ClassifyConfidence maps a floating-point confidence score to one of the
// four discrete confidence bands used in the policy matrix.
func ClassifyConfidence(score float64) ConfidenceBand {
	switch {
	case score > 0.9:
		return BandCritical
	case score > 0.7:
		return BandHigh
	case score >= 0.3:
		return BandMedium
	default:
		return BandLow
	}
}

// AssetType classifies the kind of infrastructure asset involved in a policy
// evaluation. These constants mirror the values defined in pkg/eventschema
// and are duplicated here to prevent circular imports between packages.
type AssetType string

const (
	AssetInference       AssetType = "inference"
	AssetAgentSandbox    AssetType = "agent_sandbox"
	AssetModelGateway    AssetType = "model_gateway"
	AssetBuildSystem     AssetType = "build_system"
	AssetInternalService AssetType = "internal_service"
	AssetDataStore       AssetType = "data_store"
)

// PolicyMatrixEntry binds an asset type and confidence band to the set of
// enforcement actions that should be taken when those conditions are met.
type PolicyMatrixEntry struct {
	Asset   AssetType      `json:"asset"`
	Band    ConfidenceBand `json:"band"`
	Actions []ActionType   `json:"actions"`
}

// DefaultPolicyMatrix returns the full response matrix that maps every
// combination of asset type and confidence band to the appropriate
// enforcement actions.
func DefaultPolicyMatrix() []PolicyMatrixEntry {
	return []PolicyMatrixEntry{
		// Internet-facing inference
		{AssetInference, BandLow, []ActionType{ActionDetectOnly}},
		{AssetInference, BandMedium, []ActionType{ActionIsolate}},
		{AssetInference, BandHigh, []ActionType{ActionKillReplace, ActionBlockEgress}},
		{AssetInference, BandCritical, []ActionType{ActionQuarantine, ActionRevokeCredentials, ActionFreezePipeline}},

		// Agent sandbox
		{AssetAgentSandbox, BandLow, []ActionType{ActionDetectOnly}},
		{AssetAgentSandbox, BandMedium, []ActionType{ActionIsolate}},
		{AssetAgentSandbox, BandHigh, []ActionType{ActionKillReplace}},
		{AssetAgentSandbox, BandCritical, []ActionType{ActionQuarantine, ActionRevokeCredentials}},

		// Model gateway
		{AssetModelGateway, BandLow, []ActionType{ActionDetectOnly}},
		{AssetModelGateway, BandMedium, []ActionType{ActionDetectOnly}},
		{AssetModelGateway, BandHigh, []ActionType{ActionIsolate}},
		{AssetModelGateway, BandCritical, []ActionType{ActionKillReplace, ActionBlockEgress}},

		// Build system
		{AssetBuildSystem, BandLow, []ActionType{ActionDetectOnly}},
		{AssetBuildSystem, BandMedium, []ActionType{ActionFreezePipeline}},
		{AssetBuildSystem, BandHigh, []ActionType{ActionFreezePipeline, ActionQuarantine}},
		{AssetBuildSystem, BandCritical, []ActionType{ActionFreezePipeline, ActionRevokeCredentials}},

		// Internal service
		{AssetInternalService, BandLow, []ActionType{ActionDetectOnly}},
		{AssetInternalService, BandMedium, []ActionType{ActionDetectOnly}},
		{AssetInternalService, BandHigh, []ActionType{ActionIsolate}},
		{AssetInternalService, BandCritical, []ActionType{ActionKillReplace}},

		// Data store
		{AssetDataStore, BandLow, []ActionType{ActionDetectOnly}},
		{AssetDataStore, BandMedium, []ActionType{ActionDetectOnly}},
		{AssetDataStore, BandHigh, []ActionType{ActionBlockEgress}},
		{AssetDataStore, BandCritical, []ActionType{ActionQuarantine, ActionRequireHuman}},
	}
}

// LookupActions searches the given policy matrix for an entry matching the
// specified asset type and the confidence band derived from the given score.
// If no matching entry is found, it returns a single-element slice containing
// ActionDetectOnly as a safe default.
func LookupActions(matrix []PolicyMatrixEntry, asset AssetType, confidence float64) []ActionType {
	band := ClassifyConfidence(confidence)
	for _, entry := range matrix {
		if entry.Asset == asset && entry.Band == band {
			result := make([]ActionType, len(entry.Actions))
			copy(result, entry.Actions)
			return result
		}
	}
	return []ActionType{ActionDetectOnly}
}
