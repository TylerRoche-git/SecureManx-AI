package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// CanaryBus injects test events into the detection pipeline and checks
// responses. It is typically backed by the transport.EventBus.
type CanaryBus interface {
	Emit(ctx context.Context, event eventschema.Event) error
}

// HeartbeatBus publishes signed heartbeats on a NATS subject for external
// consumers such as the watchdog process.
type HeartbeatBus interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// Sentinel monitors the integrity of the control plane itself. It runs inside
// the control plane process and performs three periodic checks:
//  1. Binary and policy file integrity verification via SHA-256 hashing
//  2. Canary event injection to detect pipeline manipulation
//  3. Heartbeat publication for external liveness/integrity proof
type Sentinel struct {
	binaryPath     string
	policyDir      string
	expectedHashes map[string]string // file path -> expected SHA-256 hex
	canaryBus      CanaryBus
	heartbeatBus   HeartbeatBus
	interval       time.Duration
	cancel         context.CancelFunc
	startTime      time.Time
	canaryOK       bool
}

// NewSentinel creates a new Sentinel that monitors the given binary and policy
// directory. It computes the initial expected hashes of both the binary and
// every file in policyDir so that subsequent verification can detect drift.
func NewSentinel(binaryPath, policyDir string, canaryBus CanaryBus, heartbeatBus HeartbeatBus) *Sentinel {
	s := &Sentinel{
		binaryPath:     binaryPath,
		policyDir:      policyDir,
		expectedHashes: make(map[string]string),
		canaryBus:      canaryBus,
		heartbeatBus:   heartbeatBus,
		interval:       30 * time.Second,
		canaryOK:       true,
	}

	// Compute initial hash of the control plane binary.
	if binaryHash, err := HashFile(binaryPath); err != nil {
		slog.Warn("sentinel: failed to hash binary, integrity checks for binary will be skipped until resolved",
			"path", binaryPath, "error", err)
	} else {
		s.expectedHashes[binaryPath] = binaryHash
		slog.Info("sentinel: binary hash recorded", "path", binaryPath, "sha256", binaryHash)
	}

	// Compute initial hash of the policy directory.
	if policyHash, err := HashDir(policyDir); err != nil {
		slog.Warn("sentinel: failed to hash policy directory, integrity checks for policies will be skipped until resolved",
			"path", policyDir, "error", err)
	} else {
		s.expectedHashes[policyDir] = policyHash
		slog.Info("sentinel: policy directory hash recorded", "path", policyDir, "sha256", policyHash)
	}

	return s
}

// Start launches the sentinel's periodic check loop. It blocks until the
// context is cancelled or Stop is called.
func (s *Sentinel) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	s.startTime = time.Now()

	slog.Info("sentinel: starting integrity monitoring",
		"interval", s.interval,
		"binary", s.binaryPath,
		"policy_dir", s.policyDir,
	)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("sentinel: stopped")
			return nil
		case <-ticker.C:
			if err := s.VerifyIntegrity(); err != nil {
				slog.Error("sentinel: integrity verification failed", "error", err)
			}

			if err := s.RunCanary(ctx); err != nil {
				slog.Error("sentinel: canary injection failed", "error", err)
				s.canaryOK = false
			} else {
				s.canaryOK = true
			}

			if err := s.PublishHeartbeat(ctx); err != nil {
				slog.Error("sentinel: heartbeat publication failed", "error", err)
			}
		}
	}
}

// Stop cancels the sentinel's check loop.
func (s *Sentinel) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// VerifyIntegrity recomputes SHA-256 hashes of the control plane binary and
// every file in the policy directory, comparing against the expected values
// recorded at startup. If ANY mismatch is detected the sentinel logs a
// CRITICAL alert and emits a self-integrity-violation event into the normal
// detection pipeline via the canary bus.
func (s *Sentinel) VerifyIntegrity() error {
	var firstErr error

	// Check the binary.
	if expected, ok := s.expectedHashes[s.binaryPath]; ok {
		current, err := HashFile(s.binaryPath)
		if err != nil {
			slog.Error("sentinel: CRITICAL: failed to hash binary during integrity check",
				"path", s.binaryPath, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("hash binary %s: %w", s.binaryPath, err)
			}
		} else if current != expected {
			slog.Error("sentinel: CRITICAL: binary integrity violation detected",
				"path", s.binaryPath,
				"expected", expected,
				"actual", current,
			)
			s.emitIntegrityViolation(s.binaryPath, expected, current)
			if firstErr == nil {
				firstErr = fmt.Errorf("binary hash mismatch for %s: expected %s, got %s", s.binaryPath, expected, current)
			}
		}
	}

	// Check the policy directory.
	if expected, ok := s.expectedHashes[s.policyDir]; ok {
		current, err := HashDir(s.policyDir)
		if err != nil {
			slog.Error("sentinel: CRITICAL: failed to hash policy directory during integrity check",
				"path", s.policyDir, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("hash policy dir %s: %w", s.policyDir, err)
			}
		} else if current != expected {
			slog.Error("sentinel: CRITICAL: policy directory integrity violation detected",
				"path", s.policyDir,
				"expected", expected,
				"actual", current,
			)
			s.emitIntegrityViolation(s.policyDir, expected, current)
			if firstErr == nil {
				firstErr = fmt.Errorf("policy dir hash mismatch for %s: expected %s, got %s", s.policyDir, expected, current)
			}
		}
	}

	return firstErr
}

// emitIntegrityViolation creates and emits a self-detection event signalling
// that a monitored file has been tampered with.
func (s *Sentinel) emitIntegrityViolation(path, expected, actual string) {
	evt := eventschema.NewEvent()
	evt.SourceType = eventschema.SourceRuntime
	evt.SourceVendor = "sentinel"
	evt.AssetID = "control-plane"
	evt.AssetType = eventschema.AssetInternalService
	evt.WorkloadID = "security-brain"
	evt.SignalClass = "self-integrity-violation"
	evt.Severity = eventschema.SeverityCritical
	evt.Confidence = 1.0
	evt.BlastRadiusHint = eventschema.BlastCluster
	evt.Observables = map[string]any{
		"path":          path,
		"expected_hash": expected,
		"actual_hash":   actual,
	}
	evt.SuggestedActions = []string{
		"investigate control plane binary and policy files for unauthorized modification",
		"consider redeploying the control plane from a trusted source",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.canaryBus.Emit(ctx, evt); err != nil {
		slog.Error("sentinel: failed to emit integrity violation event", "error", err)
	}
}

// RunCanary creates and emits a canary event designed to be absorbed by the
// pipeline without triggering an incident. The canary has very low confidence
// (0.01) which should be filtered out by the pre-filter's 0.2 threshold. If
// the pipeline produces an incident from a canary, it indicates that someone
// has modified the pre-filter rules -- a sign of compromise.
//
// For MVP the canary is emitted and logged. Full round-trip verification
// (confirming it was correctly filtered) is planned for a later iteration.
func (s *Sentinel) RunCanary(ctx context.Context) error {
	canaryID := uuid.Must(uuid.NewV7()).String()

	evt := eventschema.NewEvent()
	evt.SourceType = eventschema.SourceRuntime
	evt.SourceVendor = "sentinel"
	evt.AssetID = "control-plane"
	evt.AssetType = eventschema.AssetInternalService
	evt.WorkloadID = "security-brain"
	evt.SignalClass = "canary-test"
	evt.Severity = eventschema.SeverityLow
	evt.Confidence = 0.01
	evt.BlastRadiusHint = eventschema.BlastIsolated
	evt.Observables = map[string]any{
		"canary":    true,
		"canary_id": canaryID,
	}

	if err := s.canaryBus.Emit(ctx, evt); err != nil {
		return fmt.Errorf("emit canary event: %w", err)
	}

	slog.Debug("sentinel: canary emitted", "canary_id", canaryID)
	return nil
}

// PublishHeartbeat creates a Heartbeat struct with the current state, serializes
// it to JSON, and publishes it to the sentinel heartbeat subject for external
// verification by monitors such as the watchdog process.
func (s *Sentinel) PublishHeartbeat(ctx context.Context) error {
	binaryHash := s.expectedHashes[s.binaryPath]
	policyHash := s.expectedHashes[s.policyDir]

	hb := Heartbeat{
		Timestamp:     time.Now().UTC(),
		BinaryHash:    binaryHash,
		PolicyHash:    policyHash,
		CanaryOK:      s.canaryOK,
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
		Version:       Version,
	}

	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	if err := s.heartbeatBus.Publish(ctx, HeartbeatSubject, data); err != nil {
		return fmt.Errorf("publish heartbeat: %w", err)
	}

	slog.Debug("sentinel: heartbeat published",
		"uptime_s", hb.UptimeSeconds,
		"canary_ok", hb.CanaryOK,
	)
	return nil
}
