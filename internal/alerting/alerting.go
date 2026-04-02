// Package alerting provides a multi-sink alert routing system for the
// security-brain control plane. When incidents are created or enforcement
// actions are executed, the Router distributes notifications to every
// configured Sink (Slack, PagerDuty, generic webhooks, etc.).
package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Severity classifies the urgency of an alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert carries all the information needed to notify an external system about
// a security event or incident.
type Alert struct {
	Timestamp  time.Time         `json:"timestamp"`
	Severity   Severity          `json:"severity"`
	Title      string            `json:"title"`
	Message    string            `json:"message"`
	IncidentID string            `json:"incident_id"`
	Action     string            `json:"action"`
	Details    map[string]string `json:"details"`
}

// Sink sends alerts to an external system (Slack, PagerDuty, webhook, etc.).
type Sink interface {
	// Name returns a human-readable identifier for this sink (used in logs).
	Name() string
	// Send delivers the alert to the external system.
	Send(ctx context.Context, alert Alert) error
}

// Router distributes alerts to all configured sinks. It sends to every sink
// regardless of individual failures and returns a combined error if any fail.
type Router struct {
	sinks []Sink
}

// NewRouter creates a Router that broadcasts alerts to all provided sinks.
func NewRouter(sinks ...Sink) *Router {
	s := make([]Sink, len(sinks))
	copy(s, sinks)
	return &Router{sinks: s}
}

// Alert sends the given alert to every configured sink. It does not stop on
// the first failure; instead it collects all errors and returns them joined.
func (r *Router) Alert(ctx context.Context, alert Alert) error {
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}

	var errs []error
	for _, sink := range r.sinks {
		if err := sink.Send(ctx, alert); err != nil {
			slog.Error("alert sink failed",
				"sink", sink.Name(),
				"title", alert.Title,
				"error", err,
			)
			errs = append(errs, fmt.Errorf("sink %s: %w", sink.Name(), err))
		} else {
			slog.Info("alert delivered",
				"sink", sink.Name(),
				"title", alert.Title,
				"severity", alert.Severity,
			)
		}
	}

	return errors.Join(errs...)
}
