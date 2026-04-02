// Command adapter-falco is the Falco sensor adapter for security-brain.
// It connects to Falco's output stream (via gRPC or HTTP webhook) and forwards
// normalized runtime security events to the NATS event bus.
//
// Mode selection via FALCO_MODE:
//   - "grpc"    (default) — connects to Falco's gRPC output service
//   - "webhook"           — listens for HTTP POST from Falco's http_output
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
	"strings"
	"sync"
	"syscall"
	"time"

	falcoclient "github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/client-go/pkg/api/outputs"

	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

func main() {
	slog.Info("adapter-falco starting")

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

	mode := envOrDefault("FALCO_MODE", "grpc")
	slog.Info("adapter-falco mode selected", "mode", mode)

	switch mode {
	case "grpc":
		runGRPCMode(ctx, bus)
	case "webhook":
		runWebhookMode(ctx, bus)
	default:
		slog.Error("unknown FALCO_MODE", "mode", mode)
		os.Exit(1)
	}

	slog.Info("adapter-falco stopped")
}

// -----------------------------------------------------------------------
// gRPC mode — connects to Falco's gRPC output service
// -----------------------------------------------------------------------

func runGRPCMode(ctx context.Context, bus *transport.EventBus) {
	host := envOrDefault("FALCO_GRPC_HOST", "localhost")
	port := envOrDefault("FALCO_GRPC_PORT", "5060")
	unixSocket := envOrDefault("FALCO_GRPC_UNIX_SOCKET", "")
	certFile := envOrDefault("FALCO_GRPC_CERT", "")
	keyFile := envOrDefault("FALCO_GRPC_KEY", "")
	caFile := envOrDefault("FALCO_GRPC_CA", "")

	config := &falcoclient.Config{}

	if unixSocket != "" {
		config.UnixSocketPath = unixSocket
		slog.Info("falco gRPC connecting via unix socket", "path", unixSocket)
	} else {
		portNum := uint16(5060)
		if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
			slog.Warn("invalid FALCO_GRPC_PORT, using default 5060", "value", port)
		}
		config.Hostname = host
		config.Port = portNum
		config.CertFile = certFile
		config.KeyFile = keyFile
		config.CARootFile = caFile
		slog.Info("falco gRPC connecting via network", "host", host, "port", portNum)
	}

	fc, err := falcoclient.NewForConfig(ctx, config)
	if err != nil {
		slog.Error("failed to connect to Falco gRPC", "error", err)
		slog.Info("falling back to webhook mode due to gRPC connection failure")
		runWebhookMode(ctx, bus)
		return
	}
	defer fc.Close()

	slog.Info("adapter-falco gRPC connected, streaming events")

	watchTimeout := 30 * time.Second
	err = fc.OutputsWatch(ctx, func(res *outputs.Response) error {
		event := mapGRPCResponseToEvent(res)
		if emitErr := bus.Emit(ctx, event); emitErr != nil {
			slog.Error("failed to emit event to bus",
				"event_id", event.EventID,
				"error", emitErr,
			)
			return nil // Do not break the stream on emit errors.
		}
		slog.Info("event emitted from Falco gRPC",
			"event_id", event.EventID,
			"signal_class", event.SignalClass,
			"severity", event.Severity,
		)
		return nil
	}, watchTimeout)

	if err != nil && ctx.Err() == nil {
		slog.Error("falco gRPC stream ended with error", "error", err)
	}
}

// mapGRPCResponseToEvent converts a Falco gRPC output response to a normalized Event.
func mapGRPCResponseToEvent(res *outputs.Response) eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceRuntime
	event.SourceVendor = eventschema.VendorFalco

	if res == nil {
		return event
	}

	event.SignalClass = res.GetRule()

	priority := res.GetPriority().String()
	event.Severity = mapFalcoPriority(priority)
	event.Confidence = mapFalcoConfidence(priority)

	if ts := res.GetTime(); ts != nil {
		event.Timestamp = ts.AsTime()
	}

	event.AssetType = eventschema.AssetInternalService
	event.BlastRadiusHint = eventschema.BlastService

	// Extract output fields into observables.
	for k, v := range res.GetOutputFields() {
		event.Observables[k] = v
	}
	event.Observables["falco_output"] = res.GetOutput()
	event.Observables["falco_source"] = res.GetSource()
	event.Observables["falco_priority"] = priority

	// Extract workload identity from output fields.
	event.WorkloadID = extractWorkloadID(res.GetOutputFields())

	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("falco:rule:%s", res.GetRule()),
	)

	return event
}

// -----------------------------------------------------------------------
// HTTP webhook mode — listens for Falco HTTP output POSTs
// -----------------------------------------------------------------------

// falcoWebhookEvent represents the JSON structure of a Falco HTTP output event.
type falcoWebhookEvent struct {
	Time         string            `json:"time"`
	Priority     string            `json:"priority"`
	Rule         string            `json:"rule"`
	Output       string            `json:"output"`
	OutputFields map[string]string `json:"output_fields"`
	Source       string            `json:"source"`
	Tags         []string          `json:"tags"`
	Hostname     string            `json:"hostname"`
}

func runWebhookMode(ctx context.Context, bus *transport.EventBus) {
	addr := envOrDefault("FALCO_WEBHOOK_ADDR", ":2801")

	mux := http.NewServeMux()
	mux.HandleFunc("/", newWebhookHandler(ctx, bus))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

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
		slog.Info("adapter-falco webhook server starting", "addr", addr)
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
	slog.Info("webhook server stopped")
}

// newWebhookHandler returns an HTTP handler that accepts Falco JSON output POSTs,
// maps them to normalized Events, and publishes them to the event bus.
func newWebhookHandler(ctx context.Context, bus *transport.EventBus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB max
		if err != nil {
			slog.Error("failed to read webhook body", "error", err)
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var falcoEvent falcoWebhookEvent
		if err := json.Unmarshal(body, &falcoEvent); err != nil {
			slog.Error("failed to parse Falco webhook JSON", "error", err, "body_length", len(body))
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		event := mapWebhookEventToEvent(&falcoEvent)

		if emitErr := bus.Emit(ctx, event); emitErr != nil {
			slog.Error("failed to emit webhook event to bus",
				"event_id", event.EventID,
				"error", emitErr,
			)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("event emitted from Falco webhook",
			"event_id", event.EventID,
			"signal_class", event.SignalClass,
			"severity", event.Severity,
		)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}
}

// mapWebhookEventToEvent converts a Falco HTTP webhook JSON event to a normalized Event.
func mapWebhookEventToEvent(falcoEvent *falcoWebhookEvent) eventschema.Event {
	event := eventschema.NewEvent()
	event.SourceType = eventschema.SourceRuntime
	event.SourceVendor = eventschema.VendorFalco
	event.SignalClass = falcoEvent.Rule

	event.Severity = mapFalcoPriority(falcoEvent.Priority)
	event.Confidence = mapFalcoConfidence(falcoEvent.Priority)

	if t, err := time.Parse(time.RFC3339Nano, falcoEvent.Time); err == nil {
		event.Timestamp = t
	}

	event.AssetType = eventschema.AssetInternalService
	event.BlastRadiusHint = eventschema.BlastService

	// Copy output fields into observables.
	for k, v := range falcoEvent.OutputFields {
		event.Observables[k] = v
	}
	event.Observables["falco_output"] = falcoEvent.Output
	event.Observables["falco_source"] = falcoEvent.Source
	event.Observables["falco_priority"] = falcoEvent.Priority
	if falcoEvent.Hostname != "" {
		event.Observables["falco_hostname"] = falcoEvent.Hostname
	}
	if len(falcoEvent.Tags) > 0 {
		event.Observables["falco_tags"] = strings.Join(falcoEvent.Tags, ",")
	}

	// Extract workload ID from output fields.
	event.WorkloadID = extractWorkloadIDFromStringMap(falcoEvent.OutputFields)

	event.EvidenceRefs = append(event.EvidenceRefs,
		fmt.Sprintf("falco:rule:%s", falcoEvent.Rule),
	)

	return event
}

// -----------------------------------------------------------------------
// Shared mapping helpers
// -----------------------------------------------------------------------

// mapFalcoPriority converts a Falco priority string to a normalized Severity.
//
// Mapping:
//   - emergency, alert, critical -> SeverityCritical
//   - error                      -> SeverityHigh
//   - warning                    -> SeverityMedium
//   - notice, informational, debug -> SeverityLow
func mapFalcoPriority(priority string) eventschema.Severity {
	lower := strings.ToLower(strings.TrimSpace(priority))
	switch {
	case lower == "emergency" || lower == "alert" || lower == "critical":
		return eventschema.SeverityCritical
	case lower == "error":
		return eventschema.SeverityHigh
	case lower == "warning":
		return eventschema.SeverityMedium
	default:
		return eventschema.SeverityLow
	}
}

// mapFalcoConfidence assigns a confidence score based on the Falco priority.
// Higher priority rules get higher confidence since Falco prioritizes them
// based on rule specificity and impact.
func mapFalcoConfidence(priority string) float64 {
	lower := strings.ToLower(strings.TrimSpace(priority))
	switch {
	case lower == "emergency" || lower == "alert" || lower == "critical":
		return 0.8
	case lower == "error":
		return 0.7
	case lower == "warning":
		return 0.5
	default:
		return 0.3
	}
}

// extractWorkloadID looks for container or pod identifiers in Falco's output
// fields map (interface{} values from gRPC).
func extractWorkloadID(fields map[string]string) string {
	// Prefer Kubernetes pod name, then container ID.
	candidates := []string{
		"k8s.pod.name",
		"container.id",
		"container.name",
	}
	for _, key := range candidates {
		if v, ok := fields[key]; ok && v != "" && v != "<NA>" {
			return v
		}
	}
	return ""
}

// extractWorkloadIDFromStringMap looks for container or pod identifiers in
// Falco's output fields map (string values from webhook).
func extractWorkloadIDFromStringMap(fields map[string]string) string {
	return extractWorkloadID(fields)
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
