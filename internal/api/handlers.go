package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/security-brain/security-brain/internal/audit"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// handleHealth returns a simple JSON health check response.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListAudit queries audit records from the store with optional filters
// passed as query parameters:
//
//	phase  — filter by audit phase (detection, correlation, decision, enforcement, recovery)
//	since  — RFC 3339 timestamp for lower time bound
//	until  — RFC 3339 timestamp for upper time bound
//	limit  — maximum number of records to return (default 100)
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	var filter audit.AuditFilter

	if phase := r.URL.Query().Get("phase"); phase != "" {
		filter.Phase = eventschema.AuditPhase(phase)
	}

	if since := r.URL.Query().Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'since' parameter: expected RFC 3339 timestamp")
			return
		}
		filter.Since = t
	}

	if until := r.URL.Query().Get("until"); until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'until' parameter: expected RFC 3339 timestamp")
			return
		}
		filter.Until = t
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 {
			writeError(w, http.StatusBadRequest, "invalid 'limit' parameter: expected positive integer")
			return
		}
		filter.Limit = limit
	}

	records, err := s.auditStore.Query(r.Context(), filter)
	if err != nil {
		slog.Error("audit query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to query audit records")
		return
	}

	writeJSON(w, http.StatusOK, records)
}

// handleListPlaybooks returns all registered playbook definitions as a JSON array.
func (s *Server) handleListPlaybooks(w http.ResponseWriter, _ *http.Request) {
	pbs := s.playbooks.List()
	writeJSON(w, http.StatusOK, pbs)
}

// handleGetPlaybook returns a single playbook definition by its ID extracted
// from the URL path. Returns 404 if no playbook matches.
func (s *Server) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "playbook id is required")
		return
	}

	pb, ok := s.playbooks.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}

	writeJSON(w, http.StatusOK, pb)
}

// writeJSON serialises v as JSON with the given HTTP status code. If encoding
// fails, a 500 error is written instead.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode failed", "error", err)
	}
}

// writeError writes a JSON error response with the given HTTP status and
// message.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		slog.Error("json encode error response failed", "error", err)
	}
}
