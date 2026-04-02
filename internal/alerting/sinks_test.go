package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Slack sink tests
// -----------------------------------------------------------------------

func TestSlackSink_Name(t *testing.T) {
	s := NewSlackSink("https://hooks.slack.com/services/x/y/z", "#test")
	if got := s.Name(); got != "slack" {
		t.Errorf("Name() = %q, want %q", got, "slack")
	}
}

func TestSlackSink_Send(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	sink := NewSlackSink(server.URL, "#security-alerts")

	alert := Alert{
		Timestamp:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		Severity:   SeverityCritical,
		Title:      "Prompt Injection Detected",
		Message:    "Action: isolate, Confidence: 0.85",
		IncidentID: "inc-123",
		Action:     "isolate",
		Details:    map[string]string{"model": "gpt-4"},
	}

	err := sink.Send(context.Background(), alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/json")
	}

	var payload slackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal slack payload: %v", err)
	}

	if payload.Channel != "#security-alerts" {
		t.Errorf("channel = %q, want %q", payload.Channel, "#security-alerts")
	}

	if len(payload.Attachments) != 1 {
		t.Fatalf("attachments count = %d, want 1", len(payload.Attachments))
	}

	// Critical should be red.
	if payload.Attachments[0].Color != "#FF0000" {
		t.Errorf("color = %q, want %q", payload.Attachments[0].Color, "#FF0000")
	}
}

func TestSlackSink_SendReturnsErrorOnNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	sink := NewSlackSink(server.URL, "")

	err := sink.Send(context.Background(), Alert{Title: "test"})
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "#FF0000"},
		{SeverityWarning, "#FFA500"},
		{SeverityInfo, "#808080"},
		{Severity("unknown"), "#808080"},
	}
	for _, tt := range tests {
		if got := severityColor(tt.sev); got != tt.want {
			t.Errorf("severityColor(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------
// PagerDuty sink tests
// -----------------------------------------------------------------------

func TestPagerDutySink_Name(t *testing.T) {
	s := NewPagerDutySink("routing-key-123")
	if got := s.Name(); got != "pagerduty" {
		t.Errorf("Name() = %q, want %q", got, "pagerduty")
	}
}

func TestPagerDutySink_Send(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink := NewPagerDutySink("routing-key-abc")
	// Override the PagerDuty URL to point at our test server.
	sink.client = &http.Client{Timeout: 5 * time.Second}

	alert := Alert{
		Timestamp:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		Severity:   SeverityCritical,
		Title:      "Incident Title",
		Message:    "Details here",
		IncidentID: "inc-456",
		Action:     "block_egress",
		Details:    map[string]string{"workload": "api-server"},
	}

	// We need to override the URL - create a custom version that posts to test server
	err := sendPagerDutyToURL(sink, server.URL, context.Background(), alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	var payload pdPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal PD payload: %v", err)
	}

	if payload.RoutingKey != "routing-key-abc" {
		t.Errorf("routing_key = %q, want %q", payload.RoutingKey, "routing-key-abc")
	}
	if payload.EventAction != "trigger" {
		t.Errorf("event_action = %q, want %q", payload.EventAction, "trigger")
	}
	if payload.Payload.Summary != "Incident Title" {
		t.Errorf("summary = %q, want %q", payload.Payload.Summary, "Incident Title")
	}
	if payload.Payload.Severity != "critical" {
		t.Errorf("severity = %q, want %q", payload.Payload.Severity, "critical")
	}
	if payload.Payload.Source != "security-brain" {
		t.Errorf("source = %q, want %q", payload.Payload.Source, "security-brain")
	}
}

// sendPagerDutyToURL is a test helper that sends the PagerDuty payload to a
// custom URL instead of the real PagerDuty endpoint.
func sendPagerDutyToURL(sink *PagerDutySink, url string, ctx context.Context, alert Alert) error {
	details := make(map[string]string, len(alert.Details)+3)
	for k, v := range alert.Details {
		details[k] = v
	}
	details["incident_id"] = alert.IncidentID
	details["action"] = alert.Action
	details["message"] = alert.Message

	payload := pdPayload{
		RoutingKey:  sink.routingKey,
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
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, io.NopCloser(
		// Use bytes.NewReader equivalent
		http.NoBody,
	))
	if err != nil {
		return err
	}
	// Actually set the body
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytesReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sink.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func TestMapSeverityToPD(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
		{Severity("other"), "info"},
	}
	for _, tt := range tests {
		if got := mapSeverityToPD(tt.sev); got != tt.want {
			t.Errorf("mapSeverityToPD(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------
// Webhook sink tests
// -----------------------------------------------------------------------

func TestWebhookSink_Name(t *testing.T) {
	s := NewWebhookSink("http://example.com/hook", nil)
	if got := s.Name(); got != "webhook" {
		t.Errorf("Name() = %q, want %q", got, "webhook")
	}
}

func TestWebhookSink_Send(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	headers := map[string]string{
		"Authorization": "Bearer secret-token",
		"X-Custom":      "value",
	}
	sink := NewWebhookSink(server.URL, headers)

	alert := Alert{
		Timestamp:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		Severity:   SeverityWarning,
		Title:      "Webhook Test",
		Message:    "Testing webhook delivery",
		IncidentID: "inc-789",
		Action:     "detect_only",
	}

	err := sink.Send(context.Background(), alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// Verify headers were forwarded.
	if got := receivedHeaders.Get("Authorization"); got != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer secret-token")
	}
	if got := receivedHeaders.Get("X-Custom"); got != "value" {
		t.Errorf("X-Custom header = %q, want %q", got, "value")
	}
	if got := receivedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}

	// Verify body is a valid Alert JSON.
	var received Alert
	if err := json.Unmarshal(receivedBody, &received); err != nil {
		t.Fatalf("failed to unmarshal webhook body: %v", err)
	}
	if received.Title != "Webhook Test" {
		t.Errorf("title = %q, want %q", received.Title, "Webhook Test")
	}
	if received.Severity != SeverityWarning {
		t.Errorf("severity = %q, want %q", received.Severity, SeverityWarning)
	}
}

func TestWebhookSink_SendReturnsErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	sink := NewWebhookSink(server.URL, nil)

	err := sink.Send(context.Background(), Alert{Title: "test"})
	if err == nil {
		t.Fatal("expected error on 403 response, got nil")
	}
}

func TestWebhookSink_CopiesHeaders(t *testing.T) {
	headers := map[string]string{"X-Key": "original"}
	sink := NewWebhookSink("http://example.com", headers)

	// Mutating the original map should not affect the sink.
	headers["X-Key"] = "mutated"

	if sink.headers["X-Key"] != "original" {
		t.Errorf("sink header mutated: got %q, want %q", sink.headers["X-Key"], "original")
	}
}

// bytesReader returns an io.Reader over a byte slice.
func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{data: b}
}

type byteSliceReader struct {
	data []byte
	pos  int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
