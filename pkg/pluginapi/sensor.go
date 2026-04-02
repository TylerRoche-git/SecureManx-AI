// Package pluginapi defines the contracts between the control plane and external adapters.
package pluginapi

import (
	"context"

	"github.com/security-brain/security-brain/pkg/eventschema"
)

// EventSink receives normalized events from sensor adapters.
type EventSink interface {
	Emit(ctx context.Context, event eventschema.Event) error
}

// Sensor represents an external detection adapter that produces security events.
type Sensor interface {
	// Name returns a human-readable identifier for this sensor.
	Name() string

	// Start begins event collection. The sensor publishes events through the provided sink.
	// It blocks until ctx is cancelled or an unrecoverable error occurs.
	Start(ctx context.Context, sink EventSink) error

	// Stop gracefully shuts down the sensor, draining any buffered events.
	Stop(ctx context.Context) error

	// HealthCheck returns nil if the sensor is operating normally.
	HealthCheck(ctx context.Context) error
}
