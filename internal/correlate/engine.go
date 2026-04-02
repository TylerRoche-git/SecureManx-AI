package correlate

import (
	"context"

	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// PolicyEvaluator is Stage 3 of the decision path. It is implemented by the
// internal/policy package and injected into the Engine to avoid circular imports.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, incident *eventschema.Incident) (*policytypes.PolicyDecision, error)
}

// Engine orchestrates the three-stage decision pipeline:
//
//	Stage 1 (PreFilter)  — deterministic rule-based filtering
//	Stage 2 (Classifier) — multi-signal correlation
//	Stage 3 (PolicyEvaluator) — deterministic policy gate (external)
type Engine struct {
	preFilter  *PreFilter
	classifier *Classifier
	policy     PolicyEvaluator
}

// NewEngine creates an Engine wired to the given pre-filter, classifier, and
// policy evaluator. Any parameter may be nil if that stage should be skipped;
// however, a nil preFilter causes all events to pass through to Stage 2 and a
// nil policy causes Stage 3 to be skipped.
func NewEngine(pf *PreFilter, cl *Classifier, pe PolicyEvaluator) *Engine {
	return &Engine{
		preFilter:  pf,
		classifier: cl,
		policy:     pe,
	}
}

// Process runs the full three-stage pipeline for a single event.
//
// Stage 1: PreFilter.Evaluate — if rejected, returns nil (event is noise).
// Stage 2: Classifier.Correlate — if no incident produced, returns nil.
// Stage 3: PolicyEvaluator.Evaluate — attaches PolicyDecision to the incident.
//
// Returns the incident with a policy decision attached, or nil if no action is
// warranted at any stage.
func (e *Engine) Process(ctx context.Context, event *eventschema.Event) (*eventschema.Incident, error) {
	// Stage 1: Deterministic Pre-Filter.
	var enrichments map[string]any
	if e.preFilter != nil {
		pass, enrich := e.preFilter.Evaluate(event)
		if !pass {
			return nil, nil
		}
		enrichments = enrich
	} else {
		enrichments = make(map[string]any)
	}

	// Stage 2: Agentic Classifier (multi-signal correlation).
	if e.classifier == nil {
		return nil, nil
	}

	incident, err := e.classifier.Correlate(ctx, event, enrichments)
	if err != nil {
		return nil, err
	}
	if incident == nil {
		return nil, nil
	}

	// Stage 3: Deterministic Policy Gate.
	if e.policy != nil {
		decision, err := e.policy.Evaluate(ctx, incident)
		if err != nil {
			return nil, err
		}
		if decision != nil {
			incident.PolicyDecision = *decision
		}
	}

	return incident, nil
}
