// Command adapter-ci is the CI/CD sensor adapter for security-brain.
// It connects to NATS and is ready to receive and forward CI/CD pipeline
// security events to the control plane event bus.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/security-brain/security-brain/internal/transport"
)

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
	slog.Info("event bus initialized", "type", "ci", "bus_subject", bus != nil)

	slog.Info("adapter-ci ready, waiting for events", "nats_url", natsURL)

	// In production, this would receive CI/CD pipeline events (e.g. from
	// GitHub Actions webhooks, GitLab CI, or similar) and stream them through
	// the event bus. For MVP, it sits ready to receive and forward events.
	<-ctx.Done()

	slog.Info("adapter-ci stopped")
}

// envOrDefault returns the value of the named environment variable if it is
// non-empty, otherwise it returns the provided fallback value.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
