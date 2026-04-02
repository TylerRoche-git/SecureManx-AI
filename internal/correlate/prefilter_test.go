package correlate

import (
	"testing"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// makeTestEvent creates a minimal valid event for prefilter testing.
func makeTestEvent(signalClass string, severity eventschema.Severity, confidence float64) *eventschema.Event {
	e := eventschema.NewEvent()
	e.SourceType = eventschema.SourceRuntime
	e.AssetType = eventschema.AssetInference
	e.SignalClass = signalClass
	e.Severity = severity
	e.Confidence = confidence
	e.WorkloadID = "wl-test"
	return &e
}

func TestPreFilter_HighSeverityPasses(t *testing.T) {
	pf := NewPreFilter()
	event := makeTestEvent("some-signal", eventschema.SeverityHigh, 0.1)

	pass, _ := pf.Evaluate(event)
	if !pass {
		t.Fatal("expected high-severity event to pass prefilter")
	}
}

func TestPreFilter_LowConfidenceLowSeverityRejected(t *testing.T) {
	pf := NewPreFilter()
	// low severity, very low confidence (< 0.2), no matching signal class keywords
	event := makeTestEvent("benign-noise", eventschema.SeverityLow, 0.05)

	pass, _ := pf.Evaluate(event)
	if pass {
		t.Fatal("expected low-confidence, low-severity event to be rejected")
	}
}

func TestPreFilter_CredentialSignalPassesWithEnrichment(t *testing.T) {
	pf := NewPreFilter()
	event := makeTestEvent("credential-access-attempt", eventschema.SeverityLow, 0.1)

	pass, enrichments := pf.Evaluate(event)
	if !pass {
		t.Fatal("expected event with 'credential' signal class to pass prefilter")
	}
	cat, ok := enrichments["threat_category"]
	if !ok {
		t.Fatal("expected threat_category enrichment for credential signal")
	}
	if cat != "credential-theft" {
		t.Fatalf("expected threat_category 'credential-theft', got %q", cat)
	}
}

func TestPreFilter_ExfiltrationSignalGetsEnrichment(t *testing.T) {
	pf := NewPreFilter()
	event := makeTestEvent("data-exfiltration-attempt", eventschema.SeverityLow, 0.1)

	pass, enrichments := pf.Evaluate(event)
	if !pass {
		t.Fatal("expected event with 'exfiltration' signal class to pass prefilter")
	}
	cat, ok := enrichments["threat_category"]
	if !ok {
		t.Fatal("expected threat_category enrichment for exfiltration signal")
	}
	if cat != "data-exfiltration" {
		t.Fatalf("expected threat_category 'data-exfiltration', got %q", cat)
	}
}

func TestPreFilter_CustomRuleWorks(t *testing.T) {
	pf := NewPreFilter()
	customRule := Rule{
		Name:        "custom-canary-rule",
		SignalClass: "canary-token",
		Enrichments: map[string]any{"threat_category": "canary-triggered"},
	}
	pf.AddRule(customRule)

	// This event has very low confidence and low severity so default rules reject it,
	// but the custom rule matches on signal class with no confidence/severity requirement.
	event := makeTestEvent("canary-token-tripped", eventschema.SeverityLow, 0.01)

	pass, enrichments := pf.Evaluate(event)
	if !pass {
		t.Fatal("expected custom rule to match canary-token event")
	}
	cat, ok := enrichments["threat_category"]
	if !ok {
		t.Fatal("expected threat_category enrichment from custom rule")
	}
	if cat != "canary-triggered" {
		t.Fatalf("expected threat_category 'canary-triggered', got %q", cat)
	}
}
