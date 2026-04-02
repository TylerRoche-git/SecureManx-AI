// Command adapter-ci is the CI/CD sensor adapter for security-brain.
// It receives webhooks from CI/CD systems (GitHub Actions, GitLab CI) and
// detects supply-chain anomalies, forwarding normalized events to the NATS
// event bus.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// ciAdapter holds the shared dependencies for all webhook handlers.
type ciAdapter struct {
	bus    *transport.EventBus
	secret string
}

func main() {
	slog.Info("adapter-ci starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	natsURL := envOrDefault("NATS_URL", "nats://localhost:4222")

	client, err := transport.NewNATSClient(natsURL)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	bus := transport.NewEventBus(client)
	secret := envOrDefault("WEBHOOK_SECRET", "")

	adapter := &ciAdapter{
		bus:    bus,
		secret: secret,
	}

	addr := envOrDefault("CI_WEBHOOK_ADDR", ":8090")
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/github", adapter.handleGitHub(ctx))
	mux.HandleFunc("/webhook/gitlab", adapter.handleGitLab(ctx))
	mux.HandleFunc("/webhook/generic", adapter.handleGeneric(ctx))
	mux.HandleFunc("/healthz", handleHealthz)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("adapter-ci webhook server starting", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("webhook server error", "error", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("webhook server shutdown error", "error", err)
	}

	wg.Wait()
	slog.Info("adapter-ci stopped")
}

// ---------------------------------------------------------------------------
// GitHub Actions webhook handler
// ---------------------------------------------------------------------------

// githubWebhookPayload represents a GitHub Actions workflow_run event.
type githubWebhookPayload struct {
	Action      string              `json:"action"`
	WorkflowRun githubWorkflowRun   `json:"workflow_run"`
	Workflow    githubWorkflow       `json:"workflow"`
	Repository  githubRepository     `json:"repository"`
}

type githubWorkflowRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Event      string `json:"event"`
	Path       string `json:"path"`
}

type githubWorkflow struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type githubRepository struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
}

func (a *ciAdapter) handleGitHub(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			slog.Error("failed to read github webhook body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Verify HMAC-SHA256 signature if a secret is configured.
		if a.secret != "" {
			sigHeader := r.Header.Get("X-Hub-Signature-256")
			if !verifyGitHubSignature(body, sigHeader, a.secret) {
				slog.Warn("github webhook signature verification failed")
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}

		var payload githubWebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			slog.Error("failed to parse github webhook JSON", "error", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		events := mapGitHubToEvents(&payload)
		for _, event := range events {
			if emitErr := a.bus.Emit(ctx, event); emitErr != nil {
				slog.Error("failed to emit github event",
					"event_id", event.EventID,
					"error", emitErr,
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			slog.Info("event emitted from github webhook",
				"event_id", event.EventID,
				"signal_class", event.SignalClass,
				"severity", event.Severity,
			)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}
}

// verifyGitHubSignature validates a GitHub webhook HMAC-SHA256 signature.
// The signature header is expected in the form "sha256=<hex>".
func verifyGitHubSignature(body []byte, sigHeader, secret string) bool {
	if sigHeader == "" {
		return false
	}
	parts := strings.SplitN(sigHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return false
	}
	expectedMAC, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	actualMAC := mac.Sum(nil)
	return hmac.Equal(actualMAC, expectedMAC)
}

// mapGitHubToEvents converts a GitHub webhook payload to one or more Events.
// It may produce multiple events when multiple anomalies are detected.
func mapGitHubToEvents(payload *githubWebhookPayload) []eventschema.Event {
	var events []eventschema.Event

	run := payload.WorkflowRun
	repo := payload.Repository

	// Detect build failure.
	if run.Conclusion == "failure" || run.Conclusion == "timed_out" || run.Conclusion == "cancelled" {
		event := newCIEvent()
		event.SignalClass = "build-failure"
		event.Severity = eventschema.SeverityMedium
		event.Confidence = 0.6
		event.Observables["repository"] = repo.FullName
		event.Observables["workflow"] = run.Name
		event.Observables["run_id"] = fmt.Sprintf("%d", run.ID)
		event.Observables["status"] = run.Status
		event.Observables["conclusion"] = run.Conclusion
		event.Observables["head_sha"] = run.HeadSHA
		event.Observables["head_branch"] = run.HeadBranch
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("github:workflow_run:%d", run.ID),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			"Investigate build failure for supply-chain compromise indicators",
			"Review recent commits for unexpected dependency changes",
		)
		events = append(events, event)
	}

	// Detect workflow file modification by checking if the workflow path
	// is present in a push-triggered run. Any workflow_run event with a
	// head_sha indicates the workflow definition may have been changed.
	if run.HeadSHA != "" && (payload.Workflow.Path != "" || run.Path != "") {
		event := newCIEvent()
		event.SignalClass = "workflow-modification"
		event.Severity = eventschema.SeverityHigh
		event.Confidence = 0.5
		workflowPath := payload.Workflow.Path
		if workflowPath == "" {
			workflowPath = run.Path
		}
		event.Observables["repository"] = repo.FullName
		event.Observables["workflow"] = run.Name
		event.Observables["workflow_path"] = workflowPath
		event.Observables["head_sha"] = run.HeadSHA
		event.Observables["head_branch"] = run.HeadBranch
		event.Observables["run_id"] = fmt.Sprintf("%d", run.ID)
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("github:workflow_run:%d", run.ID),
			fmt.Sprintf("github:commit:%s", run.HeadSHA),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			"Verify workflow file changes are authorized",
			"Check if workflow modifications introduce secret exfiltration",
		)
		events = append(events, event)
	}

	// Detect dependency update events (triggered by dependabot or renovate).
	if run.Event == "pull_request" && (strings.Contains(run.HeadBranch, "dependabot") || strings.Contains(run.HeadBranch, "renovate")) {
		event := newCIEvent()
		event.SignalClass = "dependency-update"
		event.Severity = eventschema.SeverityLow
		event.Confidence = 0.4
		event.Observables["repository"] = repo.FullName
		event.Observables["head_branch"] = run.HeadBranch
		event.Observables["head_sha"] = run.HeadSHA
		event.Observables["run_id"] = fmt.Sprintf("%d", run.ID)
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("github:workflow_run:%d", run.ID),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			"Review dependency update for known vulnerabilities",
		)
		events = append(events, event)
	}

	// If no specific anomaly detected, still emit an informational event for
	// any workflow_run so the control plane has visibility.
	if len(events) == 0 {
		event := newCIEvent()
		event.SignalClass = "ci-activity"
		event.Severity = eventschema.SeverityLow
		event.Confidence = 0.2
		event.Observables["repository"] = repo.FullName
		event.Observables["workflow"] = run.Name
		event.Observables["run_id"] = fmt.Sprintf("%d", run.ID)
		event.Observables["status"] = run.Status
		event.Observables["conclusion"] = run.Conclusion
		event.Observables["action"] = payload.Action
		events = append(events, event)
	}

	return events
}

// ---------------------------------------------------------------------------
// GitLab CI webhook handler
// ---------------------------------------------------------------------------

// gitlabPipelinePayload represents a GitLab pipeline webhook event.
type gitlabPipelinePayload struct {
	ObjectKind       string               `json:"object_kind"`
	ObjectAttributes gitlabPipelineAttrs  `json:"object_attributes"`
	Project          gitlabProject        `json:"project"`
	Builds           []gitlabBuild        `json:"builds"`
}

type gitlabPipelineAttrs struct {
	ID         int64    `json:"id"`
	Ref        string   `json:"ref"`
	Status     string   `json:"status"`
	Stages     []string `json:"stages"`
	CreatedAt  string   `json:"created_at"`
	FinishedAt string   `json:"finished_at"`
	SHA        string   `json:"sha"`
	Source     string   `json:"source"`
}

type gitlabProject struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
}

type gitlabBuild struct {
	ID        int64  `json:"id"`
	Stage     string `json:"stage"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

func (a *ciAdapter) handleGitLab(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify GitLab token header.
		if a.secret != "" {
			token := r.Header.Get("X-Gitlab-Token")
			if token != a.secret {
				slog.Warn("gitlab webhook token verification failed")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			slog.Error("failed to read gitlab webhook body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var payload gitlabPipelinePayload
		if err := json.Unmarshal(body, &payload); err != nil {
			slog.Error("failed to parse gitlab webhook JSON", "error", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		events := mapGitLabToEvents(&payload)
		for _, event := range events {
			if emitErr := a.bus.Emit(ctx, event); emitErr != nil {
				slog.Error("failed to emit gitlab event",
					"event_id", event.EventID,
					"error", emitErr,
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			slog.Info("event emitted from gitlab webhook",
				"event_id", event.EventID,
				"signal_class", event.SignalClass,
				"severity", event.Severity,
			)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}
}

// mapGitLabToEvents converts a GitLab pipeline webhook to one or more Events.
func mapGitLabToEvents(payload *gitlabPipelinePayload) []eventschema.Event {
	var events []eventschema.Event

	attrs := payload.ObjectAttributes
	project := payload.Project

	// Detect failed pipeline.
	if attrs.Status == "failed" {
		event := newCIEvent()
		event.SignalClass = "build-failure"
		event.Severity = eventschema.SeverityMedium
		event.Confidence = 0.6
		event.Observables["project"] = project.PathWithNamespace
		event.Observables["pipeline_id"] = fmt.Sprintf("%d", attrs.ID)
		event.Observables["status"] = attrs.Status
		event.Observables["ref"] = attrs.Ref
		event.Observables["sha"] = attrs.SHA
		event.Observables["stages"] = strings.Join(attrs.Stages, ",")
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("gitlab:pipeline:%d", attrs.ID),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			"Investigate pipeline failure for supply-chain compromise indicators",
		)
		events = append(events, event)
	}

	// Detect security-stage failures: any build in a stage named "security",
	// "sast", "dast", "dependency_scanning", or "container_scanning" that failed.
	securityStages := map[string]bool{
		"security":             true,
		"sast":                 true,
		"dast":                 true,
		"dependency_scanning":  true,
		"container_scanning":   true,
		"secret_detection":     true,
		"license_scanning":     true,
	}
	for _, build := range payload.Builds {
		stageLower := strings.ToLower(build.Stage)
		if securityStages[stageLower] && build.Status == "failed" {
			event := newCIEvent()
			event.SignalClass = "build-failure"
			event.Severity = eventschema.SeverityHigh
			event.Confidence = 0.7
			event.Observables["project"] = project.PathWithNamespace
			event.Observables["pipeline_id"] = fmt.Sprintf("%d", attrs.ID)
			event.Observables["failed_stage"] = build.Stage
			event.Observables["failed_build"] = build.Name
			event.Observables["build_id"] = fmt.Sprintf("%d", build.ID)
			event.Observables["ref"] = attrs.Ref
			event.EvidenceRefs = append(event.EvidenceRefs,
				fmt.Sprintf("gitlab:build:%d", build.ID),
			)
			event.SuggestedActions = append(event.SuggestedActions,
				fmt.Sprintf("Review security stage '%s' failure in pipeline %d", build.Stage, attrs.ID),
			)
			events = append(events, event)
		}
	}

	// If no anomaly was detected, emit informational event.
	if len(events) == 0 {
		event := newCIEvent()
		event.SignalClass = "ci-activity"
		event.Severity = eventschema.SeverityLow
		event.Confidence = 0.2
		event.Observables["project"] = project.PathWithNamespace
		event.Observables["pipeline_id"] = fmt.Sprintf("%d", attrs.ID)
		event.Observables["status"] = attrs.Status
		event.Observables["ref"] = attrs.Ref
		events = append(events, event)
	}

	return events
}

// ---------------------------------------------------------------------------
// Generic CI webhook handler
// ---------------------------------------------------------------------------

// genericWebhookPayload represents a generic CI webhook payload for
// testing and integration with arbitrary CI systems.
type genericWebhookPayload struct {
	Source    string         `json:"source"`
	EventType string        `json:"event_type"`
	Status   string         `json:"status"`
	Metadata map[string]any `json:"metadata"`
}

func (a *ciAdapter) handleGeneric(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			slog.Error("failed to read generic webhook body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var payload genericWebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			slog.Error("failed to parse generic webhook JSON", "error", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		event := mapGenericToEvent(&payload)
		if emitErr := a.bus.Emit(ctx, event); emitErr != nil {
			slog.Error("failed to emit generic event",
				"event_id", event.EventID,
				"error", emitErr,
			)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("event emitted from generic webhook",
			"event_id", event.EventID,
			"signal_class", event.SignalClass,
			"source", payload.Source,
		)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}
}

// mapGenericToEvent converts a generic CI webhook payload to an Event.
func mapGenericToEvent(payload *genericWebhookPayload) eventschema.Event {
	event := newCIEvent()

	// Map event_type to signal class, falling back to the raw event_type.
	switch strings.ToLower(payload.EventType) {
	case "build-failure", "build_failure":
		event.SignalClass = "build-failure"
		event.Severity = eventschema.SeverityMedium
		event.Confidence = 0.5
	case "workflow-modification", "workflow_modification":
		event.SignalClass = "workflow-modification"
		event.Severity = eventschema.SeverityHigh
		event.Confidence = 0.5
	case "dependency-update", "dependency_update":
		event.SignalClass = "dependency-update"
		event.Severity = eventschema.SeverityLow
		event.Confidence = 0.4
	default:
		event.SignalClass = payload.EventType
		event.Severity = eventschema.SeverityLow
		event.Confidence = 0.3
	}

	event.Observables["source"] = payload.Source
	event.Observables["event_type"] = payload.EventType
	event.Observables["status"] = payload.Status

	// Copy all metadata into observables.
	for k, v := range payload.Metadata {
		event.Observables[fmt.Sprintf("meta_%s", k)] = v
	}

	return event
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// newCIEvent creates a new Event pre-filled with CI/CD source metadata.
func newCIEvent() eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceSupplyChain
	event.SourceVendor = eventschema.VendorCIScanner
	event.AssetType = eventschema.AssetBuildSystem
	event.BlastRadiusHint = eventschema.BlastService
	return event
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
