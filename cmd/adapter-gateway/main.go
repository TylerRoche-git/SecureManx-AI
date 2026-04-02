// Command adapter-gateway is the AI model gateway sensor adapter for
// security-brain. It receives HTTP events from a model gateway proxy and
// applies rule-based detection for prompt injection, abnormal tool use,
// data egress, and token anomalies. Detected signals are published as
// normalized events to the NATS event bus.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

func main() {
	slog.Info("adapter-gateway starting")

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

	analyzer := newGatewayAnalyzer(bus)

	addr := envOrDefault("GATEWAY_ADDR", ":8091")
	runHTTPServer(ctx, addr, analyzer)

	slog.Info("adapter-gateway stopped")
}

// -----------------------------------------------------------------------
// HTTP server
// -----------------------------------------------------------------------

func runHTTPServer(ctx context.Context, addr string, analyzer *gatewayAnalyzer) {
	mux := http.NewServeMux()
	mux.HandleFunc("/events/inference", analyzer.handleInference)
	mux.HandleFunc("/events/tool-use", analyzer.handleToolUse)
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
		slog.Info("adapter-gateway HTTP server starting", "addr", addr)
		if srvErr := server.ListenAndServe(); srvErr != nil && srvErr != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", srvErr)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if shutErr := server.Shutdown(shutdownCtx); shutErr != nil {
		slog.Error("HTTP server shutdown error", "error", shutErr)
	}

	wg.Wait()
	slog.Info("adapter-gateway HTTP server stopped")
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

// inferenceEvent represents a model inference event sent by the gateway proxy.
type inferenceEvent struct {
	RequestID  string     `json:"request_id"`
	Timestamp  string     `json:"timestamp"`
	Model      string     `json:"model"`
	UserID     string     `json:"user_id"`
	Prompt     string     `json:"prompt"`
	Response   string     `json:"response"`
	TokensIn   int        `json:"tokens_in"`
	TokensOut  int        `json:"tokens_out"`
	ToolCalls  []toolCall `json:"tool_calls"`
	LatencyMs  int        `json:"latency_ms"`
}

type toolCall struct {
	Name string `json:"name"`
	Args string `json:"args"`
}

// toolUseEvent represents a direct tool use audit event.
type toolUseEvent struct {
	RequestID string `json:"request_id"`
	Tool      string `json:"tool"`
	Args      string `json:"args"`
	UserID    string `json:"user_id"`
}

// -----------------------------------------------------------------------
// Gateway analyzer
// -----------------------------------------------------------------------

type gatewayAnalyzer struct {
	bus               *transport.EventBus
	injectionPatterns []*regexp.Regexp
	secretPatterns    []*regexp.Regexp
	dangerousTools    map[string]bool
}

func newGatewayAnalyzer(bus *transport.EventBus) *gatewayAnalyzer {
	return &gatewayAnalyzer{
		bus:               bus,
		injectionPatterns: compileInjectionPatterns(),
		secretPatterns:    compileSecretPatterns(),
		dangerousTools:    buildDangerousToolSet(),
	}
}

// -----------------------------------------------------------------------
// Prompt injection patterns
// -----------------------------------------------------------------------

func compileInjectionPatterns() []*regexp.Regexp {
	// Each entry is a pair: pattern string and a descriptive label (used for
	// logging/debugging only). The patterns are case-insensitive.
	rawPatterns := []string{
		`(?i)ignore\s+previous\s+instructions`,
		`(?i)you\s+are\s+now`,
		`(?i)system\s+prompt\s*:`,
		`(?i)\bbypass\b`,
		`(?i)\bjailbreak\b`,
		// Base64 blocks: 40+ contiguous base64 characters (indicative of
		// encoded payload injection).
		`[A-Za-z0-9+/=]{40,}`,
		// Long hex sequences: 32+ hex chars (potential hex-encoded payloads).
		`(?i)(?:0x)?[0-9a-f]{32,}`,
		// Excessive special characters: 10+ non-alphanumeric non-space in a row.
		`[^a-zA-Z0-9\s]{10,}`,
	}

	compiled := make([]*regexp.Regexp, 0, len(rawPatterns))
	for _, p := range rawPatterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}

// -----------------------------------------------------------------------
// Secret / data egress patterns
// -----------------------------------------------------------------------

func compileSecretPatterns() []*regexp.Regexp {
	rawPatterns := []string{
		// AWS access key ID (starts with AKIA, 20 chars).
		`AKIA[0-9A-Z]{16}`,
		// Generic API token / bearer token patterns.
		`(?i)(?:api[_-]?key|api[_-]?token|bearer)\s*[:=]\s*\S{16,}`,
		// PEM private key block.
		`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`,
		// GitHub personal access tokens.
		`ghp_[A-Za-z0-9]{36,}`,
		// Generic secret assignment patterns.
		`(?i)(?:secret|password|passwd)\s*[:=]\s*\S{8,}`,
	}

	compiled := make([]*regexp.Regexp, 0, len(rawPatterns))
	for _, p := range rawPatterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}

// -----------------------------------------------------------------------
// Dangerous tool set
// -----------------------------------------------------------------------

func buildDangerousToolSet() map[string]bool {
	return map[string]bool{
		"exec_code":       true,
		"shell":           true,
		"file_write":      true,
		"network_request": true,
	}
}

// -----------------------------------------------------------------------
// Inference handler
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) handleInference(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB
	if err != nil {
		slog.Error("failed to read inference body", "error", err)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var evt inferenceEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		slog.Error("failed to parse inference JSON", "error", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	events := g.analyzeInference(ctx, &evt)

	for i := range events {
		if emitErr := g.bus.Emit(ctx, events[i]); emitErr != nil {
			slog.Error("failed to emit event",
				"event_id", events[i].EventID,
				"signal_class", events[i].SignalClass,
				"error", emitErr,
			)
		} else {
			slog.Info("event emitted from gateway adapter",
				"event_id", events[i].EventID,
				"signal_class", events[i].SignalClass,
				"severity", events[i].Severity,
			)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]any{"accepted": true, "signals": len(events)}
	_ = json.NewEncoder(w).Encode(resp)
}

// analyzeInference runs all detection rules on an inference event and returns
// any security events produced.
func (g *gatewayAnalyzer) analyzeInference(ctx context.Context, evt *inferenceEvent) []eventschema.Event {
	var events []eventschema.Event

	ts := parseTimestamp(evt.Timestamp)

	// 1. Prompt injection detection.
	if injEvent, found := g.detectPromptInjection(evt, ts); found {
		events = append(events, injEvent)
	}

	// 2. Abnormal tool use detection.
	if toolEvents := g.detectAbnormalToolUse(evt, ts); len(toolEvents) > 0 {
		events = append(events, toolEvents...)
	}

	// 3. Data egress detection.
	if egressEvent, found := g.detectDataEgress(evt, ts); found {
		events = append(events, egressEvent)
	}

	// 4. Token anomaly detection.
	if tokenEvent, found := g.detectTokenAnomaly(evt, ts); found {
		events = append(events, tokenEvent)
	}

	return events
}

// -----------------------------------------------------------------------
// Detection: prompt injection
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) detectPromptInjection(evt *inferenceEvent, ts time.Time) (eventschema.Event, bool) {
	prompt := evt.Prompt
	if prompt == "" {
		return eventschema.Event{}, false
	}

	var matchedPatterns []string
	for _, pat := range g.injectionPatterns {
		if pat.MatchString(prompt) {
			matchedPatterns = append(matchedPatterns, pat.String())
		}
	}

	if len(matchedPatterns) == 0 {
		return eventschema.Event{}, false
	}

	// Confidence scales with the number of matched patterns.
	confidence := 0.3 + float64(len(matchedPatterns))*0.15
	if confidence > 0.95 {
		confidence = 0.95
	}

	severity := eventschema.SeverityMedium
	if len(matchedPatterns) >= 3 {
		severity = eventschema.SeverityHigh
	}
	if len(matchedPatterns) >= 5 {
		severity = eventschema.SeverityCritical
	}

	event := newGatewayEvent(ts)
	event.SignalClass = "prompt-injection"
	event.Severity = severity
	event.Confidence = confidence
	event.IdentityID = evt.UserID
	event.AssetType = eventschema.AssetModelGateway
	event.BlastRadiusHint = eventschema.BlastService
	event.Observables["request_id"] = evt.RequestID
	event.Observables["model"] = evt.Model
	event.Observables["user_id"] = evt.UserID
	event.Observables["matched_patterns"] = strings.Join(matchedPatterns, "; ")
	event.Observables["prompt_length"] = fmt.Sprintf("%d", utf8.RuneCountInString(prompt))
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("gateway:inference:%s", evt.RequestID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		"Block or quarantine the prompt",
		"Review user activity for "+evt.UserID,
	)

	return event, true
}

// -----------------------------------------------------------------------
// Detection: abnormal tool use
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) detectAbnormalToolUse(evt *inferenceEvent, ts time.Time) []eventschema.Event {
	var events []eventschema.Event

	// Check for dangerous tool calls.
	for _, tc := range evt.ToolCalls {
		if g.dangerousTools[tc.Name] {
			event := newGatewayEvent(ts)
			event.SignalClass = "abnormal-tool-use"
			event.Severity = eventschema.SeverityHigh
			event.Confidence = 0.8
			event.IdentityID = evt.UserID
			event.AssetType = eventschema.AssetModelGateway
			event.BlastRadiusHint = eventschema.BlastService
			event.Observables["request_id"] = evt.RequestID
			event.Observables["model"] = evt.Model
			event.Observables["user_id"] = evt.UserID
			event.Observables["dangerous_tool"] = tc.Name
			event.Observables["tool_args"] = tc.Args
			event.EvidenceRefs = append(event.EvidenceRefs,
				fmt.Sprintf("gateway:tool-use:%s:%s", evt.RequestID, tc.Name),
			)
			event.SuggestedActions = append(event.SuggestedActions,
				fmt.Sprintf("Restrict access to tool %s", tc.Name),
				"Audit recent tool invocations for user "+evt.UserID,
			)
			events = append(events, event)
		}
	}

	// Check for excessive tool call count (> 5 in a single inference).
	if len(evt.ToolCalls) > 5 {
		event := newGatewayEvent(ts)
		event.SignalClass = "abnormal-tool-use"
		event.Severity = eventschema.SeverityMedium
		event.Confidence = 0.6
		event.IdentityID = evt.UserID
		event.AssetType = eventschema.AssetModelGateway
		event.BlastRadiusHint = eventschema.BlastService
		event.Observables["request_id"] = evt.RequestID
		event.Observables["model"] = evt.Model
		event.Observables["user_id"] = evt.UserID
		event.Observables["tool_call_count"] = fmt.Sprintf("%d", len(evt.ToolCalls))

		toolNames := make([]string, 0, len(evt.ToolCalls))
		for _, tc := range evt.ToolCalls {
			toolNames = append(toolNames, tc.Name)
		}
		event.Observables["tool_names"] = strings.Join(toolNames, ", ")
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("gateway:excessive-tools:%s", evt.RequestID),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			"Rate-limit tool calls per inference",
			"Review inference request "+evt.RequestID,
		)
		events = append(events, event)
	}

	return events
}

// -----------------------------------------------------------------------
// Detection: data egress
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) detectDataEgress(evt *inferenceEvent, ts time.Time) (eventschema.Event, bool) {
	response := evt.Response
	if response == "" {
		return eventschema.Event{}, false
	}

	var findings []string

	// Check for secret patterns in the response.
	for _, pat := range g.secretPatterns {
		if pat.MatchString(response) {
			findings = append(findings, pat.String())
		}
	}

	// Check for unusually large response (> 10 KB).
	responseBytes := len(response)
	largeResponse := responseBytes > 10*1024

	if len(findings) == 0 && !largeResponse {
		return eventschema.Event{}, false
	}

	confidence := 0.5
	severity := eventschema.SeverityMedium

	if len(findings) > 0 {
		confidence = 0.7 + float64(len(findings))*0.05
		if confidence > 0.95 {
			confidence = 0.95
		}
		severity = eventschema.SeverityHigh
	}
	if largeResponse && len(findings) > 0 {
		severity = eventschema.SeverityCritical
		confidence = 0.9
	}

	event := newGatewayEvent(ts)
	event.SignalClass = "data-egress-attempt"
	event.Severity = severity
	event.Confidence = confidence
	event.IdentityID = evt.UserID
	event.AssetType = eventschema.AssetModelGateway
	event.BlastRadiusHint = eventschema.BlastService
	event.Observables["request_id"] = evt.RequestID
	event.Observables["model"] = evt.Model
	event.Observables["user_id"] = evt.UserID
	event.Observables["response_bytes"] = fmt.Sprintf("%d", responseBytes)

	if len(findings) > 0 {
		event.Observables["matched_secret_patterns"] = strings.Join(findings, "; ")
	}
	if largeResponse {
		event.Observables["large_response"] = "true"
	}

	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("gateway:data-egress:%s", evt.RequestID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		"Redact sensitive content from response",
		"Review data access policies for model "+evt.Model,
	)

	return event, true
}

// -----------------------------------------------------------------------
// Detection: token anomaly
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) detectTokenAnomaly(evt *inferenceEvent, ts time.Time) (eventschema.Event, bool) {
	if evt.TokensIn <= 0 {
		return eventschema.Event{}, false
	}

	ratio := float64(evt.TokensOut) / float64(evt.TokensIn)
	if ratio <= 10.0 {
		return eventschema.Event{}, false
	}

	event := newGatewayEvent(ts)
	event.SignalClass = "token-anomaly"
	event.Severity = eventschema.SeverityMedium
	event.Confidence = 0.6
	event.IdentityID = evt.UserID
	event.AssetType = eventschema.AssetModelGateway
	event.BlastRadiusHint = eventschema.BlastService
	event.Observables["request_id"] = evt.RequestID
	event.Observables["model"] = evt.Model
	event.Observables["user_id"] = evt.UserID
	event.Observables["tokens_in"] = fmt.Sprintf("%d", evt.TokensIn)
	event.Observables["tokens_out"] = fmt.Sprintf("%d", evt.TokensOut)
	event.Observables["ratio"] = fmt.Sprintf("%.2f", ratio)
	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("gateway:token-anomaly:%s", evt.RequestID),
	)
	event.SuggestedActions = append(event.SuggestedActions,
		"Investigate why output tokens far exceed input",
		"Check for model data leak or prompt injection",
	)

	return event, true
}

// -----------------------------------------------------------------------
// Tool-use audit handler
// -----------------------------------------------------------------------

func (g *gatewayAnalyzer) handleToolUse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		slog.Error("failed to read tool-use body", "error", err)
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var evt toolUseEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		slog.Error("failed to parse tool-use JSON", "error", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if g.dangerousTools[evt.Tool] {
		event := newGatewayEvent(time.Now().UTC())
		event.SignalClass = "abnormal-tool-use"
		event.Severity = eventschema.SeverityHigh
		event.Confidence = 0.85
		event.IdentityID = evt.UserID
		event.AssetType = eventschema.AssetModelGateway
		event.BlastRadiusHint = eventschema.BlastService
		event.Observables["request_id"] = evt.RequestID
		event.Observables["user_id"] = evt.UserID
		event.Observables["dangerous_tool"] = evt.Tool
		event.Observables["tool_args"] = evt.Args
		event.EvidenceRefs = append(event.EvidenceRefs,
			fmt.Sprintf("gateway:direct-tool-use:%s:%s", evt.RequestID, evt.Tool),
		)
		event.SuggestedActions = append(event.SuggestedActions,
			fmt.Sprintf("Restrict access to tool %s", evt.Tool),
			"Audit recent tool invocations for user "+evt.UserID,
		)

		if emitErr := g.bus.Emit(ctx, event); emitErr != nil {
			slog.Error("failed to emit tool-use event",
				"event_id", event.EventID,
				"error", emitErr,
			)
		} else {
			slog.Info("tool-use event emitted",
				"event_id", event.EventID,
				"signal_class", event.SignalClass,
				"tool", evt.Tool,
			)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"accepted":true}`))
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// newGatewayEvent creates a pre-populated Event for the gateway adapter.
func newGatewayEvent(ts time.Time) eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceApplication
	event.SourceVendor = eventschema.VendorGateway
	if !ts.IsZero() {
		event.Timestamp = ts
	}
	return event
}

// parseTimestamp attempts to parse an ISO-8601 timestamp string. If parsing
// fails it returns the current UTC time.
func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Now().UTC()
	}
	// Try RFC3339 (ISO-8601 compatible) first.
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	// Fallback: try a few common ISO-8601 variants.
	for _, layout := range []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
