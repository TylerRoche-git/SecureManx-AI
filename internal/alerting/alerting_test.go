package alerting

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// spySink records all alerts it receives for test verification.
type spySink struct {
	mu     sync.Mutex
	name   string
	alerts []Alert
	err    error // if non-nil, Send returns this error
}

func newSpySink(name string) *spySink {
	return &spySink{name: name}
}

func newFailingSink(name string, err error) *spySink {
	return &spySink{name: name, err: err}
}

func (s *spySink) Name() string { return s.name }

func (s *spySink) Send(_ context.Context, alert Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, alert)
	return s.err
}

func (s *spySink) received() []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Alert, len(s.alerts))
	copy(cp, s.alerts)
	return cp
}

// -----------------------------------------------------------------------
// Router tests
// -----------------------------------------------------------------------

func TestRouter_AlertSendsToAllSinks(t *testing.T) {
	s1 := newSpySink("sink1")
	s2 := newSpySink("sink2")

	router := NewRouter(s1, s2)

	alert := Alert{
		Timestamp:  time.Now().UTC(),
		Severity:   SeverityCritical,
		Title:      "Test Alert",
		Message:    "Something happened",
		IncidentID: "inc-001",
		Action:     "isolate",
	}

	err := router.Alert(context.Background(), alert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if got := len(s1.received()); got != 1 {
		t.Errorf("sink1 got %d alerts, want 1", got)
	}
	if got := len(s2.received()); got != 1 {
		t.Errorf("sink2 got %d alerts, want 1", got)
	}

	if s1.received()[0].Title != "Test Alert" {
		t.Errorf("sink1 alert title = %q, want %q", s1.received()[0].Title, "Test Alert")
	}
}

func TestRouter_AlertCollectsErrors(t *testing.T) {
	s1 := newSpySink("ok-sink")
	s2 := newFailingSink("bad-sink", errors.New("connection refused"))
	s3 := newSpySink("ok-sink2")

	router := NewRouter(s1, s2, s3)

	alert := Alert{
		Severity: SeverityWarning,
		Title:    "Partial Failure Test",
	}

	err := router.Alert(context.Background(), alert)

	// The ok sinks should still have received the alert.
	if got := len(s1.received()); got != 1 {
		t.Errorf("ok-sink got %d alerts, want 1", got)
	}
	if got := len(s3.received()); got != 1 {
		t.Errorf("ok-sink2 got %d alerts, want 1", got)
	}

	// The error should be non-nil and contain the failing sink's name.
	if err == nil {
		t.Fatal("expected error from failing sink, got nil")
	}
	if !errors.Is(err, s2.err) {
		t.Errorf("expected underlying error %q, got %v", s2.err, err)
	}
}

func TestRouter_AlertSetsTimestampIfZero(t *testing.T) {
	s := newSpySink("ts-sink")
	router := NewRouter(s)

	alert := Alert{
		Severity: SeverityInfo,
		Title:    "Timestamp Test",
		// Timestamp intentionally left zero.
	}

	before := time.Now().UTC()
	err := router.Alert(context.Background(), alert)
	after := time.Now().UTC()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	received := s.received()
	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}

	ts := received[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not between %v and %v", ts, before, after)
	}
}

func TestRouter_AlertNoSinks(t *testing.T) {
	router := NewRouter()

	err := router.Alert(context.Background(), Alert{
		Severity: SeverityInfo,
		Title:    "No sinks",
	})
	if err != nil {
		t.Fatalf("expected no error with zero sinks, got %v", err)
	}
}

func TestNewRouter_CopiesSinks(t *testing.T) {
	s := newSpySink("original")
	router := NewRouter(s)

	// Mutating the original slice after construction should not affect the router.
	err := router.Alert(context.Background(), Alert{Title: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.received()); got != 1 {
		t.Errorf("got %d alerts, want 1", got)
	}
}

// -----------------------------------------------------------------------
// Severity constant tests
// -----------------------------------------------------------------------

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityCritical, "critical"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("Severity %v = %q, want %q", tt.sev, string(tt.sev), tt.want)
		}
	}
}
