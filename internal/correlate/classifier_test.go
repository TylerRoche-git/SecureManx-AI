package correlate

import (
	"context"
	"testing"
	"time"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// classifierTestEvent creates a minimal event for classifier testing.
func classifierTestEvent(workload, signalClass string, severity eventschema.Severity, confidence float64) *eventschema.Event {
	e := eventschema.NewEvent()
	e.SourceType = eventschema.SourceRuntime
	e.AssetType = eventschema.AssetInference
	e.WorkloadID = workload
	e.SignalClass = signalClass
	e.Severity = severity
	e.Confidence = confidence
	return &e
}

func TestClassifier_SingleLowConfidenceNoIncident(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	event := classifierTestEvent("wl-1", "noise", eventschema.SeverityLow, 0.1)
	incident, err := cl.Correlate(ctx, event, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if incident != nil {
		t.Fatal("expected no incident for single low-confidence event")
	}
}

func TestClassifier_ThreeEventsInSameWorkloadTriggersIncident(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	events := []*eventschema.Event{
		classifierTestEvent("wl-1", "signal-a", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-1", "signal-b", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-1", "signal-c", eventschema.SeverityLow, 0.1),
	}

	var incident *eventschema.Incident
	var err error
	for _, ev := range events {
		incident, err = cl.Correlate(ctx, ev, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if incident == nil {
		t.Fatal("expected incident after 3 events in same workload")
	}
	if len(incident.ContributingEvents) != 3 {
		t.Fatalf("expected 3 contributing events, got %d", len(incident.ContributingEvents))
	}
}

func TestClassifier_CriticalSeverityTriggersImmediately(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	event := classifierTestEvent("wl-1", "critical-breach", eventschema.SeverityCritical, 0.5)
	incident, err := cl.Correlate(ctx, event, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if incident == nil {
		t.Fatal("expected incident for critical severity event")
	}
	if incident.AssetCriticality != eventschema.SeverityCritical {
		t.Fatalf("expected asset_criticality critical, got %q", incident.AssetCriticality)
	}
}

func TestClassifier_DifferentWorkloadsDontCrossCorrelate(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	// Add 2 events to workload-a and 1 to workload-b; none should trigger
	events := []*eventschema.Event{
		classifierTestEvent("wl-a", "sig-1", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-b", "sig-2", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-a", "sig-3", eventschema.SeverityLow, 0.1),
	}

	for _, ev := range events {
		incident, err := cl.Correlate(ctx, ev, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if incident != nil {
			t.Fatalf("did not expect incident for workload %q with only 2 events each", ev.WorkloadID)
		}
	}

	// Verify two separate windows exist
	if cl.ActiveWindows() != 2 {
		t.Fatalf("expected 2 active windows, got %d", cl.ActiveWindows())
	}
}

func TestClassifier_ExpiredEventsAreEvicted(t *testing.T) {
	// Use a very short window so events expire quickly
	cl := NewClassifier(100 * time.Millisecond)
	ctx := context.Background()

	// Add an event
	ev1 := classifierTestEvent("wl-1", "old-signal", eventschema.SeverityLow, 0.1)
	_, err := cl.Correlate(ctx, ev1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for the window to expire
	time.Sleep(200 * time.Millisecond)

	// Add a second event; the first should have been evicted, so we have 1 event total
	ev2 := classifierTestEvent("wl-1", "new-signal", eventschema.SeverityLow, 0.1)
	incident, err := cl.Correlate(ctx, ev2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if incident != nil {
		t.Fatal("expected no incident because old event should have been evicted")
	}
}

func TestClassifier_IncidentHasCorrectContributingEventIDs(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	events := []*eventschema.Event{
		classifierTestEvent("wl-1", "sig-a", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-1", "sig-b", eventschema.SeverityLow, 0.1),
		classifierTestEvent("wl-1", "sig-c", eventschema.SeverityLow, 0.1),
	}

	var incident *eventschema.Incident
	for _, ev := range events {
		var err error
		incident, err = cl.Correlate(ctx, ev, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if incident == nil {
		t.Fatal("expected incident after 3 events")
	}

	// Verify each original event ID is present in contributing events
	idSet := make(map[string]bool)
	for _, id := range incident.ContributingEvents {
		idSet[id.String()] = true
	}
	for _, ev := range events {
		if !idSet[ev.EventID.String()] {
			t.Fatalf("incident missing contributing event %s", ev.EventID)
		}
	}
}

func TestClassifier_ActiveWindowsCount(t *testing.T) {
	cl := NewClassifier(5 * time.Minute)
	ctx := context.Background()

	if cl.ActiveWindows() != 0 {
		t.Fatalf("expected 0 active windows initially, got %d", cl.ActiveWindows())
	}

	ev := classifierTestEvent("wl-1", "sig", eventschema.SeverityLow, 0.1)
	_, _ = cl.Correlate(ctx, ev, nil)

	if cl.ActiveWindows() != 1 {
		t.Fatalf("expected 1 active window after 1 event, got %d", cl.ActiveWindows())
	}

	ev2 := classifierTestEvent("wl-2", "sig", eventschema.SeverityLow, 0.1)
	_, _ = cl.Correlate(ctx, ev2, nil)

	if cl.ActiveWindows() != 2 {
		t.Fatalf("expected 2 active windows after events in 2 workloads, got %d", cl.ActiveWindows())
	}
}
