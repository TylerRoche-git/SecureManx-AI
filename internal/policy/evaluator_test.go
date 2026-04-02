package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// makeIncident creates a test incident with the given confidence and criticality.
func makeIncident(confidence float64, criticality eventschema.Severity) *eventschema.Incident {
	return &eventschema.Incident{
		IncidentID:         uuid.Must(uuid.NewV7()),
		ContributingEvents: []uuid.UUID{uuid.Must(uuid.NewV7())},
		ThreatHypothesis:   "test hypothesis",
		ConfidenceScore:    confidence,
		AssetCriticality:   criticality,
	}
}

func TestNewEvaluator_WithoutPolicyDir(t *testing.T) {
	e, err := NewEvaluator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.IsOPAReady() {
		t.Fatal("expected OPA not ready with empty policy dir")
	}
}

func TestNewEvaluator_WithNonexistentDir(t *testing.T) {
	e, err := NewEvaluator("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.IsOPAReady() {
		t.Fatal("expected OPA not ready with nonexistent policy dir")
	}
}

func TestNewEvaluator_WithValidRegoFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.IsOPAReady() {
		t.Fatal("expected OPA to be ready after loading valid .rego files")
	}
}

func TestNewEvaluator_WithInvalidRego(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte("this is not valid rego!!!"), 0644)
	if err != nil {
		t.Fatalf("write test file: %v", err)
	}

	e, createErr := NewEvaluator(dir)
	if createErr != nil {
		t.Fatalf("unexpected error: %v", createErr)
	}
	// Should fall back to matrix, not ready for OPA.
	if e.IsOPAReady() {
		t.Fatal("expected OPA not ready with invalid rego file")
	}
}

func TestEvaluate_NilIncident(t *testing.T) {
	e, err := NewEvaluator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, evalErr := e.Evaluate(context.Background(), nil)
	if evalErr == nil {
		t.Fatal("expected error for nil incident")
	}
}

func TestEvaluate_MatrixFallback_HighConfidenceCriticalAsset(t *testing.T) {
	e, err := NewEvaluator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.95, eventschema.SeverityCritical)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	// SeverityCritical maps to AssetInference, BandCritical (>0.9)
	// => quarantine, revoke_credentials, freeze_pipeline
	if decision.Action != policytypes.ActionQuarantine {
		t.Errorf("expected action %q, got %q", policytypes.ActionQuarantine, decision.Action)
	}
}

func TestEvaluate_MatrixFallback_LowConfidence(t *testing.T) {
	e, err := NewEvaluator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.1, eventschema.SeverityLow)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionDetectOnly {
		t.Errorf("expected action %q, got %q", policytypes.ActionDetectOnly, decision.Action)
	}
	if decision.AuthorityLevel != policytypes.AuthorityAuto {
		t.Errorf("expected authority %q, got %q", policytypes.AuthorityAuto, decision.AuthorityLevel)
	}
}

func TestEvaluate_OPA_HighConfidence_ReturnsQuarantine(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.IsOPAReady() {
		t.Fatal("expected OPA to be ready")
	}

	incident := makeIncident(0.95, eventschema.SeverityCritical)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionQuarantine {
		t.Errorf("expected action %q, got %q", policytypes.ActionQuarantine, decision.Action)
	}
}

func TestEvaluate_OPA_MediumConfidence_ReturnsIsolate(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.5, eventschema.SeverityMedium)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionIsolate {
		t.Errorf("expected action %q, got %q", policytypes.ActionIsolate, decision.Action)
	}
}

func TestEvaluate_OPA_HighConfidence_ReturnsKillReplace(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.85, eventschema.SeverityHigh)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionKillReplace {
		t.Errorf("expected action %q, got %q", policytypes.ActionKillReplace, decision.Action)
	}
}

func TestEvaluate_OPA_LowConfidence_ReturnsDetectOnly(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.1, eventschema.SeverityLow)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionDetectOnly {
		t.Errorf("expected action %q, got %q", policytypes.ActionDetectOnly, decision.Action)
	}
}

func TestEvaluate_OPA_CriticalAssetLowConfidence_RequiresHuman(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.4, eventschema.SeverityCritical)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.AuthorityLevel != policytypes.AuthorityRequiresHuman {
		t.Errorf("expected authority %q, got %q", policytypes.AuthorityRequiresHuman, decision.AuthorityLevel)
	}
}

func TestEvaluate_OPA_QuarantineCriticalAsset_RequiresHuman(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Confidence >0.9 triggers quarantine; critical asset triggers requires_human
	incident := makeIncident(0.95, eventschema.SeverityCritical)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Action != policytypes.ActionQuarantine {
		t.Errorf("expected action %q, got %q", policytypes.ActionQuarantine, decision.Action)
	}
	if decision.AuthorityLevel != policytypes.AuthorityRequiresHuman {
		t.Errorf("expected authority %q, got %q", policytypes.AuthorityRequiresHuman, decision.AuthorityLevel)
	}
}

func TestEvaluate_OPA_NonCriticalHighConfidence_AutoAuthority(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.85, eventschema.SeverityHigh)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.AuthorityLevel != policytypes.AuthorityAuto {
		t.Errorf("expected authority %q, got %q", policytypes.AuthorityAuto, decision.AuthorityLevel)
	}
}

func TestEvaluate_OPA_DecisionHasRationale(t *testing.T) {
	dir := t.TempDir()
	writeTestPolicy(t, dir)

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	incident := makeIncident(0.85, eventschema.SeverityHigh)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}

	if decision.Rationale == "" {
		t.Error("expected non-empty rationale from OPA evaluation")
	}
}

func TestReload_RefreshesPolicies(t *testing.T) {
	dir := t.TempDir()

	e, err := NewEvaluator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if e.IsOPAReady() {
		t.Fatal("expected OPA not ready before policies are written")
	}

	// Write policy files after initial creation.
	writeTestPolicy(t, dir)

	if reloadErr := e.Reload(context.Background()); reloadErr != nil {
		t.Fatalf("reload error: %v", reloadErr)
	}

	if !e.IsOPAReady() {
		t.Fatal("expected OPA to be ready after reload with valid policies")
	}

	// Verify evaluation works after reload.
	incident := makeIncident(0.85, eventschema.SeverityHigh)
	decision, evalErr := e.Evaluate(context.Background(), incident)
	if evalErr != nil {
		t.Fatalf("unexpected error: %v", evalErr)
	}
	if decision.Action != policytypes.ActionKillReplace {
		t.Errorf("expected action %q after reload, got %q", policytypes.ActionKillReplace, decision.Action)
	}
}

func TestBuildOPAInput(t *testing.T) {
	incident := makeIncident(0.75, eventschema.SeverityHigh)
	incident.ThreatHypothesis = "credential exfiltration"

	input := buildOPAInput(incident)

	confidence, ok := input["confidence_score"].(float64)
	if !ok || confidence != 0.75 {
		t.Errorf("expected confidence_score 0.75, got %v", input["confidence_score"])
	}

	criticality, ok := input["asset_criticality"].(string)
	if !ok || criticality != "high" {
		t.Errorf("expected asset_criticality 'high', got %v", input["asset_criticality"])
	}

	hypothesis, ok := input["threat_hypothesis"].(string)
	if !ok || hypothesis != "credential exfiltration" {
		t.Errorf("expected threat_hypothesis 'credential exfiltration', got %v", input["threat_hypothesis"])
	}

	eventCount, ok := input["contributing_event_count"].(int)
	if !ok || eventCount != 1 {
		t.Errorf("expected contributing_event_count 1, got %v", input["contributing_event_count"])
	}
}

func TestParseOPADecision_ValidMap(t *testing.T) {
	result := map[string]interface{}{
		"action":          "isolate",
		"authority_level": "auto",
		"rationale":       "test rationale",
	}

	decision, err := parseOPADecision(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action != policytypes.ActionIsolate {
		t.Errorf("expected action %q, got %q", policytypes.ActionIsolate, decision.Action)
	}
	if decision.AuthorityLevel != policytypes.AuthorityAuto {
		t.Errorf("expected authority %q, got %q", policytypes.AuthorityAuto, decision.AuthorityLevel)
	}
	if decision.Rationale != "test rationale" {
		t.Errorf("expected rationale 'test rationale', got %q", decision.Rationale)
	}
}

func TestParseOPADecision_MissingAction(t *testing.T) {
	result := map[string]interface{}{
		"authority_level": "auto",
	}

	_, err := parseOPADecision(result)
	if err == nil {
		t.Fatal("expected error for missing action field")
	}
}

func TestParseOPADecision_MissingAuthorityLevel(t *testing.T) {
	result := map[string]interface{}{
		"action": "isolate",
	}

	_, err := parseOPADecision(result)
	if err == nil {
		t.Fatal("expected error for missing authority_level field")
	}
}

func TestParseOPADecision_MissingRationale_DefaultsGracefully(t *testing.T) {
	result := map[string]interface{}{
		"action":          "isolate",
		"authority_level": "auto",
	}

	decision, err := parseOPADecision(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Rationale == "" {
		t.Error("expected non-empty default rationale when rationale field is missing")
	}
}

// writeTestPolicy writes the standard default.rego test policy to the given dir.
func writeTestPolicy(t *testing.T, dir string) {
	t.Helper()

	policy := `package securitybrain.policy

import rego.v1

default action := "detect_only"
default authority_level := "auto"

action := result if {
    input.confidence_score > 0.9
    result := "quarantine"
}

action := result if {
    input.confidence_score > 0.7
    input.confidence_score <= 0.9
    result := "kill_replace"
}

action := result if {
    input.confidence_score > 0.3
    input.confidence_score <= 0.7
    result := "isolate"
}

authority_level := "requires_human" if {
    input.asset_criticality == "critical"
    input.confidence_score < 0.5
}

authority_level := "requires_human" if {
    action == "quarantine"
    input.asset_criticality == "critical"
}

decision := {
    "action": action,
    "authority_level": authority_level,
    "rationale": sprintf("Policy evaluation: confidence=%.2f, criticality=%s", [input.confidence_score, input.asset_criticality])
}
`
	err := os.WriteFile(filepath.Join(dir, "default.rego"), []byte(policy), 0644)
	if err != nil {
		t.Fatalf("write test policy: %v", err)
	}
}
