// Package api provides the HTTP server for the operator API, exposing
// endpoints for health checks, audit record queries, and playbook management.
package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/security-brain/security-brain/internal/audit"
	"github.com/security-brain/security-brain/internal/incidents"
	"github.com/security-brain/security-brain/internal/playbooks"
	"github.com/security-brain/security-brain/internal/transport"
)

// Server is the HTTP server for the security-brain operator API.
type Server struct {
	httpServer    *http.Server
	mux           *http.ServeMux
	auditStore    *audit.Store
	incidentStore *incidents.Store
	playbooks     *playbooks.Registry
	eventBus      *transport.EventBus
}

// NewServer creates a Server listening on addr with routes wired to the given
// audit store, incident store, and playbook registry.
//
// Routes (Go 1.22+ ServeMux patterns):
//
//	GET /healthz                  — health check
//	GET /api/v1/audit             — query audit records
//	GET /api/v1/playbooks         — list all playbooks
//	GET /api/v1/playbooks/{id}    — get a specific playbook by ID
//	GET  /api/v1/incidents         — list incidents with optional filters
//	GET  /api/v1/incidents/{id}    — get a specific incident by ID
//	POST /api/v1/events            — inject a raw event into the pipeline
func NewServer(addr string, auditStore *audit.Store, incidentStore *incidents.Store, playbookReg *playbooks.Registry, eventBus *transport.EventBus) *Server {
	mux := http.NewServeMux()

	s := &Server{
		mux:           mux,
		auditStore:    auditStore,
		incidentStore: incidentStore,
		playbooks:     playbookReg,
		eventBus:      eventBus,
	}

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)
	mux.HandleFunc("GET /api/v1/playbooks", s.handleListPlaybooks)
	mux.HandleFunc("GET /api/v1/playbooks/{id}", s.handleGetPlaybook)
	mux.HandleFunc("GET /api/v1/incidents", s.handleListIncidents)
	mux.HandleFunc("GET /api/v1/incidents/{id}", s.handleGetIncident)
	mux.HandleFunc("POST /api/v1/events", s.handleInjectEvent)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s
}

// Start begins serving HTTP requests. It blocks until ctx is cancelled, at
// which point it initiates a graceful shutdown of the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("api server starting", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("api server shutting down")
		return s.Stop(context.Background())
	}
}

// Stop gracefully shuts down the HTTP server, allowing in-flight requests to
// complete within the deadline provided by ctx.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
