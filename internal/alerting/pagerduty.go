package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutySink delivers alerts to PagerDuty via the Events API v2.
type PagerDutySink struct {
	routingKey string
	client     *http.Client
}

// NewPagerDutySink creates a Sink that triggers PagerDuty incidents using the
// provided routing (integration) key.
func NewPagerDutySink(routingKey string) *PagerDutySink {
	return &PagerDutySink{
		routingKey: routingKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns "pagerduty".
func (s *PagerDutySink) Name() string { return "pagerduty" }

// pdPayload models the PagerDuty Events API v2 trigger request.
type pdPayload struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	Payload     pdInner   `json:"payload"`
}

type pdInner struct {
	Summary       string            `json:"summary"`
	Severity      string            `json:"severity"`
	Source        string            `json:"source"`
	Timestamp     string            `json:"timestamp,omitempty"`
	CustomDetails map[string]string `json:"custom_details,omitempty"`
}

// mapSeverityToPD maps alerting.Severity to PagerDuty severity strings.
// PagerDuty accepts: critical, error, warning, info.
func mapSeverityToPD(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// Send triggers a PagerDuty event for the given alert.
func (s *PagerDutySink) Send(ctx context.Context, alert Alert) error {
	details := make(map[string]string, len(alert.Details)+3)
	for k, v := range alert.Details {
		details[k] = v
	}
	details["incident_id"] = alert.IncidentID
	details["action"] = alert.Action
	details["message"] = alert.Message

	payload := pdPayload{
		RoutingKey:  s.routingKey,
		EventAction: "trigger",
		Payload: pdInner{
			Summary:       alert.Title,
			Severity:      mapSeverityToPD(alert.Severity),
			Source:        "security-brain",
			Timestamp:     alert.Timestamp.Format(time.RFC3339),
			CustomDetails: details,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("pagerduty marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pagerDutyEventsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Error("pagerduty non-200", "status", resp.StatusCode, "body", string(respBody))
		return fmt.Errorf("pagerduty returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
