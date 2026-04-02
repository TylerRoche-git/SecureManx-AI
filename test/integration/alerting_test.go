//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/security-brain/security-brain/internal/alerting"
)

// slackPayload mirrors the internal Slack payload structure for test
// deserialization. Defined here to avoid exporting internal types.
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

// TestAlerting_SlackWebhook_SendsFormattedMessage spins up a test HTTP server,
// creates a SlackSink pointing to it, sends an alert, and verifies the
// received POST has correct JSON structure (channel, text, attachments, color).
func TestAlerting_SlackWebhook_SendsFormattedMessage(t *testing.T) {
	var receivedBody []byte
	var receivedMethod string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	sink := alerting.NewSlackSink(server.URL, "#security-alerts")

	alert := alerting.Alert{
		Timestamp:  time.Date(2026, 4, 2, 14, 30, 0, 0, time.UTC),
		Severity:   alerting.SeverityCritical,
		Title:      "Credential Exfiltration Detected",
		Message:    "Action: quarantine, Confidence: 0.95",
		IncidentID: "inc-integration-001",
		Action:     "quarantine",
		Details:    map[string]string{"workload": "default/secret-stealer"},
	}

	err := sink.Send(context.Background(), alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// Verify HTTP method.
	if receivedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", receivedMethod)
	}

	// Verify Content-Type.
	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}

	// Parse the payload.
	var payload slackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal Slack payload: %v", err)
	}

	// Verify channel.
	if payload.Channel != "#security-alerts" {
		t.Errorf("channel = %q, want #security-alerts", payload.Channel)
	}

	// Verify text contains severity and title.
	if payload.Text == "" {
		t.Error("text should not be empty")
	}

	// Verify attachments.
	if len(payload.Attachments) != 1 {
		t.Fatalf("attachments count = %d, want 1", len(payload.Attachments))
	}

	// Critical severity should produce red color.
	if payload.Attachments[0].Color != "#FF0000" {
		t.Errorf("attachment color = %q, want #FF0000 (red for critical)", payload.Attachments[0].Color)
	}

	// Verify fields contain title and incident ID.
	fieldMap := make(map[string]string)
	for _, f := range payload.Attachments[0].Fields {
		fieldMap[f.Title] = f.Value
	}
	if fieldMap["Title"] != "Credential Exfiltration Detected" {
		t.Errorf("field Title = %q, want %q", fieldMap["Title"], "Credential Exfiltration Detected")
	}
	if fieldMap["Incident ID"] != "inc-integration-001" {
		t.Errorf("field Incident ID = %q, want %q", fieldMap["Incident ID"], "inc-integration-001")
	}
	if fieldMap["Action"] != "quarantine" {
		t.Errorf("field Action = %q, want %q", fieldMap["Action"], "quarantine")
	}
}

// TestAlerting_WebhookSink_SendsAlert spins up a test HTTP server, creates
// a WebhookSink with custom headers, sends an alert, and verifies the POST
// contains the correct headers and JSON body.
func TestAlerting_WebhookSink_SendsAlert(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	customHeaders := map[string]string{
		"Authorization": "Bearer integration-test-token",
		"X-Source":       "security-brain",
	}
	sink := alerting.NewWebhookSink(server.URL, customHeaders)

	alert := alerting.Alert{
		Timestamp:  time.Date(2026, 4, 2, 15, 0, 0, 0, time.UTC),
		Severity:   alerting.SeverityWarning,
		Title:      "Anomalous Egress Pattern",
		Message:    "Multiple connections to unknown IPs detected",
		IncidentID: "inc-integration-002",
		Action:     "isolate",
		Details:    map[string]string{"destination_count": "15"},
	}

	err := sink.Send(context.Background(), alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// Verify custom headers.
	if got := receivedHeaders.Get("Authorization"); got != "Bearer integration-test-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer integration-test-token")
	}
	if got := receivedHeaders.Get("X-Source"); got != "security-brain" {
		t.Errorf("X-Source = %q, want %q", got, "security-brain")
	}
	if got := receivedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}

	// Verify body is a valid Alert JSON.
	var received alerting.Alert
	if err := json.Unmarshal(receivedBody, &received); err != nil {
		t.Fatalf("failed to unmarshal webhook body: %v", err)
	}
	if received.Title != "Anomalous Egress Pattern" {
		t.Errorf("title = %q, want %q", received.Title, "Anomalous Egress Pattern")
	}
	if received.Severity != alerting.SeverityWarning {
		t.Errorf("severity = %q, want %q", received.Severity, alerting.SeverityWarning)
	}
	if received.IncidentID != "inc-integration-002" {
		t.Errorf("incident_id = %q, want %q", received.IncidentID, "inc-integration-002")
	}
}

// TestAlerting_Router_SendsToAllSinks creates three test HTTP servers
// (simulating different sinks), creates a Router with all three, sends
// an alert, and verifies every server received the alert.
func TestAlerting_Router_SendsToAllSinks(t *testing.T) {
	type serverRecord struct {
		mu       sync.Mutex
		received bool
		body     []byte
	}

	records := make([]*serverRecord, 3)
	servers := make([]*httptest.Server, 3)

	for i := range records {
		rec := &serverRecord{}
		records[i] = rec
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			var err error
			rec.body, err = io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("server %d: failed to read body: %v", i, err)
			}
			rec.received = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	// Create three different sink types pointing to our test servers.
	sinks := []alerting.Sink{
		alerting.NewSlackSink(servers[0].URL, "#alerts"),
		alerting.NewWebhookSink(servers[1].URL, map[string]string{"X-Test": "1"}),
		alerting.NewWebhookSink(servers[2].URL, map[string]string{"X-Test": "2"}),
	}

	router := alerting.NewRouter(sinks...)

	alert := alerting.Alert{
		Timestamp:  time.Now().UTC(),
		Severity:   alerting.SeverityCritical,
		Title:      "Multi-Sink Broadcast Test",
		Message:    "All sinks should receive this",
		IncidentID: "inc-integration-003",
		Action:     "kill_replace",
	}

	err := router.Alert(context.Background(), alert)
	if err != nil {
		t.Fatalf("Router.Alert() error = %v", err)
	}

	// Verify all servers received the alert.
	for i, rec := range records {
		rec.mu.Lock()
		got := rec.received
		bodyLen := len(rec.body)
		rec.mu.Unlock()

		if !got {
			t.Errorf("server %d did not receive the alert", i)
		}
		if bodyLen == 0 {
			t.Errorf("server %d received empty body", i)
		}
	}
}
