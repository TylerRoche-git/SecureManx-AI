package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// EventBus provides typed pub/sub over the NATS transport.
// It implements pluginapi.EventSink.
type EventBus struct {
	client *NATSClient
}

// NewEventBus wraps a NATSClient with typed event operations.
func NewEventBus(client *NATSClient) *EventBus {
	return &EventBus{client: client}
}

// Emit publishes a raw event to the raw events subject.
// This satisfies the pluginapi.EventSink interface.
func (b *EventBus) Emit(ctx context.Context, event eventschema.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	return b.client.Publish(ctx, SubjectRawEvents, data)
}

// PublishNormalized publishes a normalised event.
func (b *EventBus) PublishNormalized(ctx context.Context, event *eventschema.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal normalized event: %w", err)
	}
	return b.client.Publish(ctx, SubjectNormalizedEvents, data)
}

// PublishIncident publishes a correlated incident.
func (b *EventBus) PublishIncident(ctx context.Context, incident *eventschema.Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}
	return b.client.Publish(ctx, SubjectIncidents, data)
}

// PublishEnforcementAction publishes an enforcement action for adapter consumption.
func (b *EventBus) PublishEnforcementAction(ctx context.Context, data []byte) error {
	return b.client.Publish(ctx, SubjectEnforcementActions, data)
}

// SubscribeNormalized subscribes to normalised events and calls handler for each.
func (b *EventBus) SubscribeNormalized(ctx context.Context, consumer string, handler func(eventschema.Event)) (jetstream.ConsumeContext, error) {
	return b.client.Subscribe(ctx, StreamEvents, SubjectNormalizedEvents, consumer, func(msg jetstream.Msg) {
		var event eventschema.Event
		if err := json.Unmarshal(msg.Data(), &event); err != nil {
			msg.Nak()
			return
		}
		handler(event)
		msg.Ack()
	})
}

// SubscribeIncidents subscribes to incidents and calls handler for each.
func (b *EventBus) SubscribeIncidents(ctx context.Context, consumer string, handler func(eventschema.Incident)) (jetstream.ConsumeContext, error) {
	return b.client.Subscribe(ctx, StreamIncidents, SubjectIncidents, consumer, func(msg jetstream.Msg) {
		var incident eventschema.Incident
		if err := json.Unmarshal(msg.Data(), &incident); err != nil {
			msg.Nak()
			return
		}
		handler(incident)
		msg.Ack()
	})
}
