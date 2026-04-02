// Package ingest consumes raw security events from NATS, normalises them, and
// republishes the validated events on the normalised-events subject.
package ingest

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// Normalizer converts raw event bytes into a validated Event.
type Normalizer interface {
	Normalize(raw []byte) (*eventschema.Event, error)
}

// Ingester subscribes to raw events, normalises them, and publishes the result.
type Ingester struct {
	bus        *transport.EventBus
	client     *transport.NATSClient
	normalizer Normalizer
	cancel     context.CancelFunc
	consumeCtx jetstream.ConsumeContext
}

// NewIngester creates an Ingester wired to the given NATS client, event bus,
// and normalizer implementation.
func NewIngester(client *transport.NATSClient, bus *transport.EventBus, normalizer Normalizer) *Ingester {
	return &Ingester{
		bus:        bus,
		client:     client,
		normalizer: normalizer,
	}
}

// Start subscribes to raw events via the NATS client and begins processing.
// For each message the normalizer is called, the result is validated with
// eventschema.ValidateEvent, and the normalised event is published on the bus.
// On any error the message is nak'd so NATS can redeliver it.
func (i *Ingester) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	i.cancel = cancel

	cc, err := i.client.Subscribe(ctx, transport.StreamEvents, transport.SubjectRawEvents, "ingest-normalizer", func(msg jetstream.Msg) {
		event, normErr := i.normalizer.Normalize(msg.Data())
		if normErr != nil {
			slog.Error("normalize failed", "error", normErr)
			_ = msg.Nak()
			return
		}

		if valErr := eventschema.ValidateEvent(event); valErr != nil {
			slog.Error("validation failed", "error", valErr)
			_ = msg.Nak()
			return
		}

		if pubErr := i.bus.PublishNormalized(ctx, event); pubErr != nil {
			slog.Error("publish normalized failed", "error", pubErr)
			_ = msg.Nak()
			return
		}

		if ackErr := msg.Ack(); ackErr != nil {
			slog.Error("ack failed", "error", ackErr)
		}
	})
	if err != nil {
		cancel()
		return fmt.Errorf("subscribe raw events: %w", err)
	}

	i.consumeCtx = cc
	return nil
}

// Stop gracefully shuts down the ingester by cancelling its subscription and
// draining in-flight processing.
func (i *Ingester) Stop(_ context.Context) error {
	if i.consumeCtx != nil {
		i.consumeCtx.Stop()
	}
	if i.cancel != nil {
		i.cancel()
	}
	return nil
}
