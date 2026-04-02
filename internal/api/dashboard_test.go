package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleDashboard_ServesHTML(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type text/html; charset=utf-8, got %q", ct)
	}

	body := rec.Body.String()
	if len(body) == 0 {
		t.Fatal("expected non-empty response body")
	}

	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("response body missing <!DOCTYPE html>")
	}

	if !strings.Contains(body, "Security Brain") {
		t.Error("response body missing 'Security Brain' title")
	}
}

func TestHandleDashboard_ContainsAllViews(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	body := rec.Body.String()

	views := []string{
		"view-dashboard",
		"view-incidents",
		"view-audit",
		"view-playbooks",
		"view-test",
	}

	for _, view := range views {
		if !strings.Contains(body, view) {
			t.Errorf("response body missing view: %s", view)
		}
	}
}

func TestHandleDashboard_ContainsAPIEndpoints(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	body := rec.Body.String()

	endpoints := []string{
		"/healthz",
		"/api/v1/incidents",
		"/api/v1/audit",
		"/api/v1/playbooks",
		"/api/v1/events",
	}

	for _, ep := range endpoints {
		if !strings.Contains(body, ep) {
			t.Errorf("response body missing API endpoint reference: %s", ep)
		}
	}
}

func TestHandleDashboard_NoExternalResources(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	body := rec.Body.String()

	externalPatterns := []string{
		"cdn.jsdelivr.net",
		"cdnjs.cloudflare.com",
		"unpkg.com",
		"googleapis.com/css",
		"<link rel=\"stylesheet\" href=\"http",
		"<script src=\"http",
	}

	for _, pattern := range externalPatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("response body contains external resource reference: %s", pattern)
		}
	}
}

func TestHandleDashboard_InlineCSSAndJS(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "<style>") {
		t.Error("response body missing inline <style> tag")
	}

	if !strings.Contains(body, "<script>") {
		t.Error("response body missing inline <script> tag")
	}
}

func TestHandleDashboard_ThemeColors(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	body := rec.Body.String()

	colors := []string{
		"#1a1a2e",
		"#16213e",
		"#0f3460",
		"#e94560",
		"#4ecca3",
		"#ffc107",
	}

	for _, color := range colors {
		if !strings.Contains(body, color) {
			t.Errorf("response body missing theme color: %s", color)
		}
	}
}

func TestDashboardHTML_EmbedNotEmpty(t *testing.T) {
	if len(dashboardHTML) == 0 {
		t.Fatal("dashboardHTML embed is empty")
	}

	if len(dashboardHTML) < 1000 {
		t.Fatalf("dashboardHTML embed seems too small: %d bytes", len(dashboardHTML))
	}
}

func TestHandleDashboard_DashboardAliasRoute(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for /dashboard alias, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Security Brain") {
		t.Error("/dashboard alias did not serve dashboard content")
	}
}
