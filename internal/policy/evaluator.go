package policy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// Evaluator implements the correlate.PolicyEvaluator interface using the
// hardcoded policy matrix. OPA/Rego integration is reserved for a future phase;
// if .rego files are present in the policy directory they are noted in logs but
// evaluation still falls back to matrix-based lookup.
type Evaluator struct {
	matrix    []policytypes.PolicyMatrixEntry
	policyDir string
}

// NewEvaluator creates an Evaluator loaded with the default policy matrix.
// If policyDir is non-empty and contains .rego files, a log message is emitted
// acknowledging their presence, but evaluation uses the matrix for the MVP.
func NewEvaluator(policyDir string) (*Evaluator, error) {
	e := &Evaluator{
		matrix:    policytypes.DefaultPolicyMatrix(),
		policyDir: policyDir,
	}

	if policyDir != "" {
		policies, err := LoadPoliciesFromDir(policyDir)
		if err != nil {
			slog.Warn("failed to scan policy directory", "dir", policyDir, "error", err)
		} else if len(policies) > 0 {
			slog.Info("OPA policy files found; using matrix-based evaluation for MVP",
				"dir", policyDir,
				"count", len(policies),
			)
		}
	}

	return e, nil
}

// Evaluate looks up the appropriate enforcement actions from the policy matrix
// based on the incident's asset criticality and confidence score.
//
// The incident's AssetCriticality (a Severity value) is mapped to a
// policytypes.AssetType for the matrix lookup. The first (highest priority)
// action from the lookup result becomes the decision's action.
//
// Authority is set to AuthorityRequiresHuman when the action is require_human
// or when confidence is below 0.5 on critical assets. All other cases use
// AuthorityAuto.
func (e *Evaluator) Evaluate(_ context.Context, incident *eventschema.Incident) (*policytypes.PolicyDecision, error) {
	if incident == nil {
		return nil, fmt.Errorf("incident must not be nil")
	}

	assetType := severityToAssetType(incident.AssetCriticality)
	actions := policytypes.LookupActions(e.matrix, assetType, incident.ConfidenceScore)

	if len(actions) == 0 {
		return &policytypes.PolicyDecision{
			Action:         policytypes.ActionDetectOnly,
			AuthorityLevel: policytypes.AuthorityAuto,
			Rationale:      "no matching policy entry; defaulting to detect-only",
		}, nil
	}

	primaryAction := actions[0]
	authority := determineAuthority(primaryAction, incident.ConfidenceScore, incident.AssetCriticality)

	rationale := fmt.Sprintf(
		"matrix lookup: asset=%s confidence=%.2f band=%s -> action=%s",
		assetType,
		incident.ConfidenceScore,
		bandLabel(policytypes.ClassifyConfidence(incident.ConfidenceScore)),
		primaryAction,
	)

	return &policytypes.PolicyDecision{
		Action:         primaryAction,
		AuthorityLevel: authority,
		Rationale:      rationale,
	}, nil
}

// Reload refreshes the policy matrix. In the MVP this reloads the hardcoded
// defaults; future versions will re-parse OPA policies from disk.
func (e *Evaluator) Reload(_ context.Context) error {
	e.matrix = policytypes.DefaultPolicyMatrix()

	if e.policyDir != "" {
		policies, err := LoadPoliciesFromDir(e.policyDir)
		if err != nil {
			slog.Warn("failed to scan policy directory during reload", "dir", e.policyDir, "error", err)
		} else if len(policies) > 0 {
			slog.Info("OPA policy files found during reload; still using matrix for MVP",
				"dir", e.policyDir,
				"count", len(policies),
			)
		}
	}

	slog.Info("policy matrix reloaded")
	return nil
}

// severityToAssetType maps an eventschema.Severity (used as AssetCriticality
// on an Incident) to a policytypes.AssetType for matrix lookup. This is a
// simplification for the MVP; the real mapping will come from the event's
// asset_type field propagated to the incident.
func severityToAssetType(severity eventschema.Severity) policytypes.AssetType {
	switch severity {
	case eventschema.SeverityCritical:
		return policytypes.AssetInference
	case eventschema.SeverityHigh:
		return policytypes.AssetModelGateway
	case eventschema.SeverityMedium:
		return policytypes.AssetInternalService
	case eventschema.SeverityLow:
		return policytypes.AssetInternalService
	default:
		return policytypes.AssetInternalService
	}
}

// determineAuthority decides whether a given action can be executed
// automatically or requires human approval. Actions of type require_human
// always need a human. Additionally, when confidence is below 0.5 on critical
// assets, human approval is required as a safety measure.
func determineAuthority(action policytypes.ActionType, confidence float64, criticality eventschema.Severity) policytypes.AuthorityLevel {
	if action == policytypes.ActionRequireHuman {
		return policytypes.AuthorityRequiresHuman
	}
	if confidence < 0.5 && criticality == eventschema.SeverityCritical {
		return policytypes.AuthorityRequiresHuman
	}
	return policytypes.AuthorityAuto
}

// bandLabel returns a human-readable label for a confidence band.
func bandLabel(band policytypes.ConfidenceBand) string {
	switch band {
	case policytypes.BandLow:
		return "low"
	case policytypes.BandMedium:
		return "medium"
	case policytypes.BandHigh:
		return "high"
	case policytypes.BandCritical:
		return "critical"
	default:
		return "unknown"
	}
}
