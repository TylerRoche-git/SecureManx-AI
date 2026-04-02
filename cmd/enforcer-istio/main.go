// Command enforcer-istio is the Istio enforcement adapter for security-brain.
// It subscribes to enforcement actions from the event bus and executes
// containment and remediation operations via Istio service mesh policies.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

func main() {
	slog.Info("enforcer-istio starting")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	natsURL := envOrDefault("NATS_URL", "nats://localhost:4222")

	client, err := transport.NewNATSClient(natsURL)
	if err != nil {
		slog.Error("failed to connect to NATS", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	if err := client.CreateAllStreams(ctx); err != nil {
		slog.Error("failed to create JetStream streams", "error", err)
		os.Exit(1)
	}

	// Subscribe to enforcement actions.
	_, err = client.Subscribe(ctx, transport.StreamEnforcement, transport.SubjectEnforcementActions, "enforcer-istio", func(msg jetstream.Msg) {
		var action policytypes.EnforcementAction
		if unmarshalErr := json.Unmarshal(msg.Data(), &action); unmarshalErr != nil {
			slog.Error("unmarshal enforcement action", "error", unmarshalErr)
			if nakErr := msg.Nak(); nakErr != nil {
				slog.Error("failed to nak message", "error", nakErr)
			}
			return
		}

		slog.Info("received enforcement action",
			"action_id", action.ActionID,
			"type", action.Type,
			"targets", action.Targets,
		)

		// In production, this would apply Istio AuthorizationPolicies,
		// DestinationRules, or VirtualServices to isolate or restrict
		// traffic for compromised workloads. For MVP, log and ack.
		if ackErr := msg.Ack(); ackErr != nil {
			slog.Error("failed to ack message", "error", ackErr)
		}
	})
	if err != nil {
		slog.Error("failed to subscribe to enforcement actions", "error", err)
		os.Exit(1)
	}

	slog.Info("enforcer-istio ready, listening for enforcement actions", "nats_url", natsURL)

	<-ctx.Done()

	slog.Info("enforcer-istio stopped")
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
