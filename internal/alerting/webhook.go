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

// WebhookSink delivers alerts as JSON to a generic HTTP endpoint.
type WebhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhookSink creates a Sink that POSTs the full Alert as JSON to the
// configured URL. Custom headers (e.g. Authorization) are included in every
// request.
func NewWebhookSink(url string, headers map[string]string) *WebhookSink {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &WebhookSink{
		url:     url,
		headers: h,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns "webhook".
func (s *WebhookSink) Name() string { return "webhook" }

// Send POSTs the JSON-serialized Alert to the configured URL.
func (s *WebhookSink) Send(ctx context.Context, alert Alert) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		slog.Error("webhook non-2xx", "url", s.url, "status", resp.StatusCode, "body", string(respBody))
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
