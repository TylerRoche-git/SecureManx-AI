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

// SlackSink delivers alerts to a Slack channel via an incoming webhook URL.
type SlackSink struct {
	webhookURL string
	channel    string
	client     *http.Client
}

// NewSlackSink creates a Sink that posts formatted messages to the given Slack
// incoming webhook URL. The channel parameter overrides the webhook's default
// channel (set to "" to use the webhook default).
func NewSlackSink(webhookURL, channel string) *SlackSink {
	return &SlackSink{
		webhookURL: webhookURL,
		channel:    channel,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns "slack".
func (s *SlackSink) Name() string { return "slack" }

// slackPayload models the JSON body sent to a Slack incoming webhook.
type slackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Fields []slackField `json:"fields"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// severityColor maps alert severity to Slack attachment sidebar colour.
func severityColor(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "#FF0000" // red
	case SeverityWarning:
		return "#FFA500" // orange
	default:
		return "#808080" // gray for info / unknown
	}
}

// Send posts the alert to Slack.
func (s *SlackSink) Send(ctx context.Context, alert Alert) error {
	fields := []slackField{
		{Title: "Title", Value: alert.Title, Short: false},
		{Title: "Severity", Value: string(alert.Severity), Short: true},
		{Title: "Incident ID", Value: alert.IncidentID, Short: true},
		{Title: "Action", Value: alert.Action, Short: true},
		{Title: "Timestamp", Value: alert.Timestamp.Format(time.RFC3339), Short: true},
	}

	if alert.Message != "" {
		fields = append(fields, slackField{Title: "Message", Value: alert.Message, Short: false})
	}

	for k, v := range alert.Details {
		fields = append(fields, slackField{Title: k, Value: v, Short: true})
	}

	payload := slackPayload{
		Channel: s.channel,
		Text:    fmt.Sprintf("[%s] %s", alert.Severity, alert.Title),
		Attachments: []slackAttachment{
			{
				Color:  severityColor(alert.Severity),
				Fields: fields,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack http: %w", err)
	}
	defer resp.Body.Close()

	// Slack returns 200 with body "ok" on success.
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Error("slack webhook non-200", "status", resp.StatusCode, "body", string(respBody))
		return fmt.Errorf("slack webhook returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
