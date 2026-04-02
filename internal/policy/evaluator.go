package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// Evaluator implements the correlate.PolicyEvaluator interface using a
// dual-mode strategy: it first attempts OPA/Rego evaluation if compiled
// policies are available, then falls back to the hardcoded policy matrix.
type Evaluator struct {
	matrix    []policytypes.PolicyMatrixEntry
	policyDir string

	mu            sync.RWMutex
	preparedQuery *rego.PreparedEvalQuery
	opaReady      bool
}

// NewEvaluator creates an Evaluator loaded with the default policy matrix
// and, if policyDir is non-empty and contains valid .rego files, compiles
// them for OPA-based evaluation. If OPA compilation fails, evaluation
// gracefully falls back to the matrix.
func NewEvaluator(policyDir string) (*Evaluator, error) {
	e := &Evaluator{
		matrix:    policytypes.DefaultPolicyMatrix(),
		policyDir: policyDir,
	}

	if policyDir != "" {
		if err := e.compileOPAPolicies(context.Background()); err != nil {
			slog.Warn("OPA policy compilation failed, using matrix fallback",
				"dir", policyDir,
				"error", err,
			)
		}
	}

	return e, nil
}

// compileOPAPolicies loads all .rego files from the policy directory,
// compiles them, and prepares a query for evaluation.
func (e *Evaluator) compileOPAPolicies(ctx context.Context) error {
	policies, err := LoadPoliciesFromDir(e.policyDir)
	if err != nil {
		return fmt.Errorf("load policies from %s: %w", e.policyDir, err)
	}

	if len(policies) == 0 {
		slog.Info("no .rego policy files found", "dir", e.policyDir)
		return nil
	}

	// Build rego options with all loaded modules.
	options := []func(*rego.Rego){
		rego.Query("data.securitybrain.policy.decision"),
	}
	for _, pf := range policies {
		options = append(options, rego.Module(pf.Path, pf.Content))
	}

	r := rego.New(options...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare OPA evaluation query: %w", err)
	}

	e.mu.Lock()
	e.preparedQuery = &prepared
	e.opaReady = true
	e.mu.Unlock()

	slog.Info("OPA policies compiled and ready for evaluation",
		"dir", e.policyDir,
		"policy_count", len(policies),
	)

	return nil
}

// Evaluate determines the policy decision for the given incident. It first
// attempts OPA/Rego evaluation if policies are compiled; on failure or if
// no policies are loaded, it falls back to the hardcoded matrix lookup.
func (e *Evaluator) Evaluate(ctx context.Context, incident *eventschema.Incident) (*policytypes.PolicyDecision, error) {
	if incident == nil {
		return nil, fmt.Errorf("incident must not be nil")
	}

	e.mu.RLock()
	ready := e.opaReady
	query := e.preparedQuery
	e.mu.RUnlock()

	if ready && query != nil {
		decision, err := e.evaluateOPA(ctx, query, incident)
		if err != nil {
			slog.Warn("OPA evaluation failed, falling back to matrix",
				"incident_id", incident.IncidentID,
				"error", err,
			)
		} else {
			return decision, nil
		}
	}

	return e.evaluateMatrix(incident), nil
}

// evaluateOPA runs the prepared OPA query against the incident data and
// parses the result into a PolicyDecision.
func (e *Evaluator) evaluateOPA(ctx context.Context, query *rego.PreparedEvalQuery, incident *eventschema.Incident) (*policytypes.PolicyDecision, error) {
	inputMap := buildOPAInput(incident)

	rs, err := query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("OPA eval: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("OPA returned no results")
	}

	resultMap, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("OPA result is not a map: %T", rs[0].Expressions[0].Value)
	}

	decision, err := parseOPADecision(resultMap)
	if err != nil {
		return nil, fmt.Errorf("parse OPA decision: %w", err)
	}

	slog.Info("OPA policy evaluation succeeded",
		"incident_id", incident.IncidentID,
		"action", decision.Action,
		"authority_level", decision.AuthorityLevel,
	)

	return decision, nil
}

// buildOPAInput constructs the input map for OPA evaluation from an Incident.
func buildOPAInput(incident *eventschema.Incident) map[string]interface{} {
	return map[string]interface{}{
		"confidence_score":        incident.ConfidenceScore,
		"asset_criticality":       string(incident.AssetCriticality),
		"threat_hypothesis":       incident.ThreatHypothesis,
		"contributing_event_count": len(incident.ContributingEvents),
	}
}

// parseOPADecision extracts action, authority_level, and rationale from the
// OPA result map and converts them to a PolicyDecision.
func parseOPADecision(result map[string]interface{}) (*policytypes.PolicyDecision, error) {
	actionRaw, ok := result["action"]
	if !ok {
		return nil, fmt.Errorf("OPA result missing 'action' field")
	}
	actionStr, ok := actionRaw.(string)
	if !ok {
		return nil, fmt.Errorf("OPA 'action' field is not a string: %T", actionRaw)
	}

	authorityRaw, ok := result["authority_level"]
	if !ok {
		return nil, fmt.Errorf("OPA result missing 'authority_level' field")
	}
	authorityStr, ok := authorityRaw.(string)
	if !ok {
		return nil, fmt.Errorf("OPA 'authority_level' field is not a string: %T", authorityRaw)
	}

	rationaleStr := "OPA policy evaluation"
	if rationaleRaw, exists := result["rationale"]; exists {
		if s, isStr := rationaleRaw.(string); isStr {
			rationaleStr = s
		}
	}

	return &policytypes.PolicyDecision{
		Action:         policytypes.ActionType(actionStr),
		AuthorityLevel: policytypes.AuthorityLevel(authorityStr),
		Rationale:      rationaleStr,
	}, nil
}

// evaluateMatrix performs the original matrix-based policy lookup as a
// fallback when OPA is unavailable or fails.
func (e *Evaluator) evaluateMatrix(incident *eventschema.Incident) *policytypes.PolicyDecision {
	assetType := severityToAssetType(incident.AssetCriticality)
	actions := policytypes.LookupActions(e.matrix, assetType, incident.ConfidenceScore)

	if len(actions) == 0 {
		return &policytypes.PolicyDecision{
			Action:         policytypes.ActionDetectOnly,
			AuthorityLevel: policytypes.AuthorityAuto,
			Rationale:      "no matching policy entry; defaulting to detect-only",
		}
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
	}
}

// Reload re-reads policies from disk and recompiles the OPA query. The
// matrix is also refreshed from the hardcoded defaults. If OPA compilation
// fails during reload, the evaluator retains its previous compiled query
// and logs a warning.
func (e *Evaluator) Reload(ctx context.Context) error {
	e.matrix = policytypes.DefaultPolicyMatrix()

	if e.policyDir != "" {
		if err := e.compileOPAPolicies(ctx); err != nil {
			slog.Warn("OPA policy recompilation failed during reload, retaining previous state",
				"dir", e.policyDir,
				"error", err,
			)
		}
	}

	slog.Info("policy evaluator reloaded",
		"policy_dir", e.policyDir,
		"opa_ready", e.opaReady,
	)
	return nil
}

// IsOPAReady reports whether OPA policies are compiled and ready for evaluation.
func (e *Evaluator) IsOPAReady() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.opaReady
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
