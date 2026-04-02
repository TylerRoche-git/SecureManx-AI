package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

func TestMapFalcoPriority_Emergency(t *testing.T) {
	got := mapFalcoPriority("Emergency")
	if got != eventschema.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", got)
	}
}

func TestMapFalcoPriority_Alert(t *testing.T) {
	got := mapFalcoPriority("alert")
	if got != eventschema.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", got)
	}
}

func TestMapFalcoPriority_Critical(t *testing.T) {
	got := mapFalcoPriority("CRITICAL")
	if got != eventschema.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", got)
	}
}

func TestMapFalcoPriority_Error(t *testing.T) {
	got := mapFalcoPriority("Error")
	if got != eventschema.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", got)
	}
}

func TestMapFalcoPriority_Warning(t *testing.T) {
	got := mapFalcoPriority("Warning")
	if got != eventschema.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", got)
	}
}

func TestMapFalcoPriority_Notice(t *testing.T) {
	got := mapFalcoPriority("Notice")
	if got != eventschema.SeverityLow {
		t.Errorf("expected SeverityLow, got %q", got)
	}
}

func TestMapFalcoPriority_Info(t *testing.T) {
	got := mapFalcoPriority("Informational")
	if got != eventschema.SeverityLow {
		t.Errorf("expected SeverityLow, got %q", got)
	}
}

func TestMapFalcoPriority_Debug(t *testing.T) {
	got := mapFalcoPriority("Debug")
	if got != eventschema.SeverityLow {
		t.Errorf("expected SeverityLow, got %q", got)
	}
}

func TestMapFalcoConfidence_CriticalPriority(t *testing.T) {
	got := mapFalcoConfidence("critical")
	if got != 0.8 {
		t.Errorf("expected 0.8, got %f", got)
	}
}

func TestMapFalcoConfidence_Error(t *testing.T) {
	got := mapFalcoConfidence("error")
	if got != 0.7 {
		t.Errorf("expected 0.7, got %f", got)
	}
}

func TestMapFalcoConfidence_Warning(t *testing.T) {
	got := mapFalcoConfidence("warning")
	if got != 0.5 {
		t.Errorf("expected 0.5, got %f", got)
	}
}

func TestMapFalcoConfidence_Low(t *testing.T) {
	got := mapFalcoConfidence("notice")
	if got != 0.3 {
		t.Errorf("expected 0.3, got %f", got)
	}
}

func TestExtractWorkloadID_PodName(t *testing.T) {
	fields := map[string]string{
		"k8s.pod.name":  "my-pod-abc",
		"container.id":  "abc123",
		"container.name": "my-container",
	}
	got := extractWorkloadID(fields)
	if got != "my-pod-abc" {
		t.Errorf("expected 'my-pod-abc', got %q", got)
	}
}

func TestExtractWorkloadID_ContainerID(t *testing.T) {
	fields := map[string]string{
		"container.id":  "abc123",
		"container.name": "my-container",
	}
	got := extractWorkloadID(fields)
	if got != "abc123" {
		t.Errorf("expected 'abc123', got %q", got)
	}
}

func TestExtractWorkloadID_ContainerName(t *testing.T) {
	fields := map[string]string{
		"container.name": "my-container",
	}
	got := extractWorkloadID(fields)
	if got != "my-container" {
		t.Errorf("expected 'my-container', got %q", got)
	}
}

func TestExtractWorkloadID_Empty(t *testing.T) {
	fields := map[string]string{
		"proc.name": "bash",
	}
	got := extractWorkloadID(fields)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestExtractWorkloadID_SkipsNAValues(t *testing.T) {
	fields := map[string]string{
		"k8s.pod.name": "<NA>",
		"container.id": "real-id",
	}
	got := extractWorkloadID(fields)
	if got != "real-id" {
		t.Errorf("expected 'real-id', got %q", got)
	}
}

func TestMapGRPCResponseToEvent_NilResponse(t *testing.T) {
	event := mapGRPCResponseToEvent(nil)
	if event.SourceType != eventschema.SourceRuntime {
		t.Errorf("expected SourceRuntime, got %q", event.SourceType)
	}
	if event.SourceVendor != eventschema.VendorFalco {
		t.Errorf("expected VendorFalco, got %q", event.SourceVendor)
	}
}

func TestMapGRPCResponseToEvent_Fields(t *testing.T) {
	res := &outputs.Response{
		Rule:   "Terminal shell in container",
		Output: "A shell was spawned in a container",
		Source: "syscall",
		OutputFields: map[string]string{
			"container.id":   "abc123",
			"container.name": "test-container",
			"proc.name":      "bash",
		},
	}
	event := mapGRPCResponseToEvent(res)

	if event.SignalClass != "Terminal shell in container" {
		t.Errorf("expected rule name as signal class, got %q", event.SignalClass)
	}
	if event.SourceType != eventschema.SourceRuntime {
		t.Errorf("expected SourceRuntime, got %q", event.SourceType)
	}
	if event.SourceVendor != eventschema.VendorFalco {
		t.Errorf("expected VendorFalco, got %q", event.SourceVendor)
	}
	if event.AssetType != eventschema.AssetInternalService {
		t.Errorf("expected AssetInternalService, got %q", event.AssetType)
	}
	if event.WorkloadID != "abc123" {
		t.Errorf("expected workload ID 'abc123', got %q", event.WorkloadID)
	}
	if event.Observables["falco_output"] != "A shell was spawned in a container" {
		t.Errorf("expected falco_output observable, got %v", event.Observables["falco_output"])
	}
	if event.Observables["falco_source"] != "syscall" {
		t.Errorf("expected falco_source 'syscall', got %v", event.Observables["falco_source"])
	}
	if len(event.EvidenceRefs) == 0 {
		t.Error("expected at least one evidence ref")
	}
}

func TestMapWebhookEventToEvent_FullEvent(t *testing.T) {
	falcoEvent := &falcoWebhookEvent{
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Priority: "Warning",
		Rule:     "Unexpected outbound connection",
		Output:   "Outbound connection detected",
		Source:   "syscall",
		Tags:     []string{"network", "mitre_exfiltration"},
		Hostname: "worker-node-1",
		OutputFields: map[string]string{
			"k8s.pod.name":  "suspicious-pod",
			"container.id":  "def456",
			"fd.sip":        "10.0.0.1",
			"fd.sport":      "443",
		},
	}

	event := mapWebhookEventToEvent(falcoEvent)

	if event.SignalClass != "Unexpected outbound connection" {
		t.Errorf("expected rule name, got %q", event.SignalClass)
	}
	if event.Severity != eventschema.SeverityMedium {
		t.Errorf("expected SeverityMedium for Warning, got %q", event.Severity)
	}
	if event.Confidence != 0.5 {
		t.Errorf("expected confidence 0.5 for Warning, got %f", event.Confidence)
	}
	if event.WorkloadID != "suspicious-pod" {
		t.Errorf("expected workload ID 'suspicious-pod', got %q", event.WorkloadID)
	}
	if event.Observables["falco_hostname"] != "worker-node-1" {
		t.Errorf("expected hostname in observables, got %v", event.Observables["falco_hostname"])
	}
	if event.Observables["falco_tags"] != "network,mitre_exfiltration" {
		t.Errorf("expected tags in observables, got %v", event.Observables["falco_tags"])
	}
	if event.SourceType != eventschema.SourceRuntime {
		t.Errorf("expected SourceRuntime, got %q", event.SourceType)
	}
	if event.SourceVendor != eventschema.VendorFalco {
		t.Errorf("expected VendorFalco, got %q", event.SourceVendor)
	}
}

func TestMapWebhookEventToEvent_CriticalPriority(t *testing.T) {
	falcoEvent := &falcoWebhookEvent{
		Priority: "Critical",
		Rule:     "Container escape attempt",
		Source:   "syscall",
	}
	event := mapWebhookEventToEvent(falcoEvent)

	if event.Severity != eventschema.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", event.Severity)
	}
	if event.Confidence != 0.8 {
		t.Errorf("expected confidence 0.8, got %f", event.Confidence)
	}
}

func TestWebhookHandler_RejectsGet(t *testing.T) {
	handler := newWebhookHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestWebhookHandler_RejectsInvalidJSON(t *testing.T) {
	handler := newWebhookHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMapWebhookEventToEvent_ParsesTimestamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	falcoEvent := &falcoWebhookEvent{
		Time:     now.Format(time.RFC3339Nano),
		Priority: "Error",
		Rule:     "Test rule",
		Source:   "syscall",
	}

	event := mapWebhookEventToEvent(falcoEvent)

	if event.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp after parsing RFC3339 time")
	}
	// Allow up to 1ms tolerance for parsing.
	diff := event.Timestamp.Sub(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Millisecond {
		t.Errorf("timestamp mismatch: expected %v, got %v", now, event.Timestamp)
	}
}

func TestMapWebhookEventToEvent_NoTags(t *testing.T) {
	falcoEvent := &falcoWebhookEvent{
		Priority: "Warning",
		Rule:     "Test rule",
		Source:   "syscall",
	}

	event := mapWebhookEventToEvent(falcoEvent)

	if _, ok := event.Observables["falco_tags"]; ok {
		t.Error("expected no falco_tags observable when tags are empty")
	}
}

func TestMapWebhookEventToEvent_NoHostname(t *testing.T) {
	falcoEvent := &falcoWebhookEvent{
		Priority: "Warning",
		Rule:     "Test rule",
		Source:   "syscall",
	}

	event := mapWebhookEventToEvent(falcoEvent)

	if _, ok := event.Observables["falco_hostname"]; ok {
		t.Error("expected no falco_hostname observable when hostname is empty")
	}
}

func TestEnvOrDefault_ReturnsDefault(t *testing.T) {
	got := envOrDefault("NONEXISTENT_TEST_VAR_XYZ", "default_value")
	if got != "default_value" {
		t.Errorf("expected 'default_value', got %q", got)
	}
}
