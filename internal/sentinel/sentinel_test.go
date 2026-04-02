package sentinel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// mockCanaryBus records all emitted events for inspection.
type mockCanaryBus struct {
	mu     sync.Mutex
	events []eventschema.Event
}

func (m *mockCanaryBus) Emit(_ context.Context, event eventschema.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockCanaryBus) getEvents() []eventschema.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]eventschema.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

// mockHeartbeatBus records all published messages.
type mockHeartbeatBus struct {
	mu       sync.Mutex
	messages []publishedMessage
}

type publishedMessage struct {
	subject string
	data    []byte
}

func (m *mockHeartbeatBus) Publish(_ context.Context, subject string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, publishedMessage{subject: subject, data: data})
	return nil
}

func (m *mockHeartbeatBus) getMessages() []publishedMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]publishedMessage, len(m.messages))
	copy(cp, m.messages)
	return cp
}

// setupTestSentinel creates a temporary binary and policy directory with known
// contents, then constructs a Sentinel with mock buses.
func setupTestSentinel(t *testing.T) (*Sentinel, *mockCanaryBus, *mockHeartbeatBus) {
	t.Helper()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "control-plane.bin")
	policyDir := filepath.Join(dir, "policies")

	if err := os.WriteFile(binaryPath, []byte("binary-content-v1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("deny: true"), 0644); err != nil {
		t.Fatal(err)
	}

	canary := &mockCanaryBus{}
	heartbeat := &mockHeartbeatBus{}
	s := NewSentinel(binaryPath, policyDir, canary, heartbeat)

	return s, canary, heartbeat
}

func TestNewSentinel_RecordsInitialHashes(t *testing.T) {
	s, _, _ := setupTestSentinel(t)

	if len(s.expectedHashes) != 2 {
		t.Fatalf("expected 2 initial hashes, got %d", len(s.expectedHashes))
	}

	binaryHash, ok := s.expectedHashes[s.binaryPath]
	if !ok || binaryHash == "" {
		t.Error("binary hash not recorded")
	}

	policyHash, ok := s.expectedHashes[s.policyDir]
	if !ok || policyHash == "" {
		t.Error("policy directory hash not recorded")
	}
}

func TestNewSentinel_DefaultInterval(t *testing.T) {
	s, _, _ := setupTestSentinel(t)
	if s.interval != 30*time.Second {
		t.Errorf("expected interval 30s, got %v", s.interval)
	}
}

func TestVerifyIntegrity_PassesWhenUnmodified(t *testing.T) {
	s, canary, _ := setupTestSentinel(t)

	err := s.VerifyIntegrity()
	if err != nil {
		t.Fatalf("VerifyIntegrity returned error for unmodified files: %v", err)
	}

	events := canary.getEvents()
	if len(events) != 0 {
		t.Errorf("expected no events for clean integrity check, got %d", len(events))
	}
}

func TestVerifyIntegrity_DetectsBinaryTampering(t *testing.T) {
	s, canary, _ := setupTestSentinel(t)

	// Tamper with the binary.
	if err := os.WriteFile(s.binaryPath, []byte("TAMPERED-BINARY"), 0644); err != nil {
		t.Fatal(err)
	}

	err := s.VerifyIntegrity()
	if err == nil {
		t.Fatal("expected error for tampered binary, got nil")
	}

	events := canary.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 integrity violation event, got %d", len(events))
	}

	evt := events[0]
	if evt.SignalClass != "self-integrity-violation" {
		t.Errorf("expected signal_class self-integrity-violation, got %s", evt.SignalClass)
	}
	if evt.Severity != eventschema.SeverityCritical {
		t.Errorf("expected severity critical, got %s", evt.Severity)
	}
	if evt.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", evt.Confidence)
	}
	if evt.SourceType != eventschema.SourceRuntime {
		t.Errorf("expected source_type runtime, got %s", evt.SourceType)
	}
	if evt.AssetType != eventschema.AssetInternalService {
		t.Errorf("expected asset_type internal_service, got %s", evt.AssetType)
	}

	path, ok := evt.Observables["path"]
	if !ok || path != s.binaryPath {
		t.Errorf("expected path observable to be %s, got %v", s.binaryPath, path)
	}
}

func TestVerifyIntegrity_DetectsPolicyTampering(t *testing.T) {
	s, canary, _ := setupTestSentinel(t)

	// Tamper with a policy file.
	policyFile := filepath.Join(s.policyDir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("deny: false # attacker changed this"), 0644); err != nil {
		t.Fatal(err)
	}

	err := s.VerifyIntegrity()
	if err == nil {
		t.Fatal("expected error for tampered policy dir, got nil")
	}

	events := canary.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 integrity violation event, got %d", len(events))
	}

	if events[0].SignalClass != "self-integrity-violation" {
		t.Errorf("expected signal_class self-integrity-violation, got %s", events[0].SignalClass)
	}
}

func TestVerifyIntegrity_DetectsBothBinaryAndPolicyTampering(t *testing.T) {
	s, canary, _ := setupTestSentinel(t)

	// Tamper with both.
	if err := os.WriteFile(s.binaryPath, []byte("TAMPERED"), 0644); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(s.policyDir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}

	err := s.VerifyIntegrity()
	if err == nil {
		t.Fatal("expected error for multiple tampering, got nil")
	}

	events := canary.getEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 integrity violation events, got %d", len(events))
	}
}

func TestRunCanary_EmitsLowConfidenceEvent(t *testing.T) {
	s, canary, _ := setupTestSentinel(t)

	ctx := context.Background()
	if err := s.RunCanary(ctx); err != nil {
		t.Fatalf("RunCanary returned error: %v", err)
	}

	events := canary.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 canary event, got %d", len(events))
	}

	evt := events[0]
	if evt.SignalClass != "canary-test" {
		t.Errorf("expected signal_class canary-test, got %s", evt.SignalClass)
	}
	if evt.Confidence != 0.01 {
		t.Errorf("expected confidence 0.01, got %f", evt.Confidence)
	}
	if evt.Severity != eventschema.SeverityLow {
		t.Errorf("expected severity low, got %s", evt.Severity)
	}
	if evt.AssetType != eventschema.AssetInternalService {
		t.Errorf("expected asset_type internal_service, got %s", evt.AssetType)
	}

	canaryFlag, ok := evt.Observables["canary"]
	if !ok || canaryFlag != true {
		t.Error("canary observable not set to true")
	}

	canaryID, ok := evt.Observables["canary_id"]
	if !ok || canaryID == "" {
		t.Error("canary_id observable not set")
	}
}

func TestPublishHeartbeat_PublishesToCorrectSubject(t *testing.T) {
	s, _, hbBus := setupTestSentinel(t)
	s.startTime = time.Now().Add(-60 * time.Second) // simulate 60s uptime
	s.canaryOK = true

	ctx := context.Background()
	if err := s.PublishHeartbeat(ctx); err != nil {
		t.Fatalf("PublishHeartbeat returned error: %v", err)
	}

	msgs := hbBus.getMessages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 heartbeat message, got %d", len(msgs))
	}

	if msgs[0].subject != HeartbeatSubject {
		t.Errorf("expected subject %s, got %s", HeartbeatSubject, msgs[0].subject)
	}
}

func TestPublishHeartbeat_ContainsExpectedFields(t *testing.T) {
	s, _, hbBus := setupTestSentinel(t)
	s.startTime = time.Now().Add(-120 * time.Second)
	s.canaryOK = true

	ctx := context.Background()
	if err := s.PublishHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}

	msgs := hbBus.getMessages()
	if len(msgs) == 0 {
		t.Fatal("no heartbeat messages")
	}

	var hb Heartbeat
	if err := json.Unmarshal(msgs[0].data, &hb); err != nil {
		t.Fatalf("failed to unmarshal heartbeat: %v", err)
	}

	if hb.Timestamp.IsZero() {
		t.Error("heartbeat timestamp is zero")
	}
	if hb.BinaryHash == "" {
		t.Error("heartbeat binary_hash is empty")
	}
	if hb.PolicyHash == "" {
		t.Error("heartbeat policy_hash is empty")
	}
	if !hb.CanaryOK {
		t.Error("heartbeat canary_ok should be true")
	}
	if hb.UptimeSeconds < 119 {
		t.Errorf("expected uptime >= 119s, got %d", hb.UptimeSeconds)
	}
	if hb.Version != Version {
		t.Errorf("expected version %s, got %s", Version, hb.Version)
	}
}

func TestPublishHeartbeat_ReflectsCanaryFailure(t *testing.T) {
	s, _, hbBus := setupTestSentinel(t)
	s.startTime = time.Now()
	s.canaryOK = false

	ctx := context.Background()
	if err := s.PublishHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}

	msgs := hbBus.getMessages()
	var hb Heartbeat
	if err := json.Unmarshal(msgs[0].data, &hb); err != nil {
		t.Fatal(err)
	}

	if hb.CanaryOK {
		t.Error("heartbeat canary_ok should be false when canary failed")
	}
}

func TestSentinel_StartAndStop(t *testing.T) {
	s, _, _ := setupTestSentinel(t)
	s.interval = 50 * time.Millisecond // fast ticks for testing

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx)
	}()

	// Let it run for a few ticks.
	time.Sleep(200 * time.Millisecond)

	s.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sentinel did not stop within timeout")
	}
}

func TestSentinel_LoopRunsAllThreeChecks(t *testing.T) {
	s, canary, hbBus := setupTestSentinel(t)
	s.interval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx)
	}()

	// Wait for at least one tick to complete all three checks.
	time.Sleep(200 * time.Millisecond)
	s.Stop()
	<-done

	// Canary should have been emitted at least once.
	events := canary.getEvents()
	if len(events) == 0 {
		t.Error("expected at least one canary event from the loop")
	}

	// At least one canary event should be a canary-test.
	foundCanary := false
	for _, e := range events {
		if e.SignalClass == "canary-test" {
			foundCanary = true
			break
		}
	}
	if !foundCanary {
		t.Error("no canary-test event found among emitted events")
	}

	// Heartbeat should have been published at least once.
	msgs := hbBus.getMessages()
	if len(msgs) == 0 {
		t.Error("expected at least one heartbeat message from the loop")
	}
}

func TestNewSentinel_HandlesNonexistentBinaryGracefully(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatal(err)
	}

	canary := &mockCanaryBus{}
	hb := &mockHeartbeatBus{}

	// Should not panic when binary does not exist.
	s := NewSentinel("/nonexistent/binary", policyDir, canary, hb)

	// Binary hash should not be recorded.
	if _, ok := s.expectedHashes["/nonexistent/binary"]; ok {
		t.Error("should not record hash for nonexistent binary")
	}

	// Policy hash should still be recorded.
	if _, ok := s.expectedHashes[policyDir]; !ok {
		t.Error("policy hash should be recorded even when binary is missing")
	}
}

func TestNewSentinel_HandlesNonexistentPolicyDirGracefully(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "binary")
	if err := os.WriteFile(binaryPath, []byte("bin"), 0644); err != nil {
		t.Fatal(err)
	}

	canary := &mockCanaryBus{}
	hb := &mockHeartbeatBus{}

	s := NewSentinel(binaryPath, "/nonexistent/policies", canary, hb)

	if _, ok := s.expectedHashes[binaryPath]; !ok {
		t.Error("binary hash should be recorded")
	}
	if _, ok := s.expectedHashes["/nonexistent/policies"]; ok {
		t.Error("should not record hash for nonexistent policy directory")
	}
}
