package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/internal/audit"
	"github.com/security-brain/security-brain/internal/incidents"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// handleHealth returns a JSON health check response including sentinel status
// and the current control plane version.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "ok",
		"sentinel": "active",
		"version":  "0.1.0",
	})
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

// handleListIncidents queries incidents from the store with optional filters
// passed as query parameters:
//
//	status          — filter by execution status (pending, executing, completed, failed, rolled_back)
//	min_confidence  — minimum confidence score (float, 0.0–1.0)
//	since           — RFC 3339 timestamp for lower time bound
//	until           — RFC 3339 timestamp for upper time bound
//	limit           — maximum number of incidents to return (default 100)
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	var filter incidents.IncidentFilter

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = eventschema.ExecutionStatus(status)
	}

	if minConf := r.URL.Query().Get("min_confidence"); minConf != "" {
		val, err := strconv.ParseFloat(minConf, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'min_confidence' parameter: expected float")
			return
		}
		filter.MinConfidence = val
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

	results, err := s.incidentStore.Query(r.Context(), filter)
	if err != nil {
		slog.Error("incident query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to query incidents")
		return
	}

	writeJSON(w, http.StatusOK, results)
}

// handleGetIncident retrieves a single incident by its UUID, extracted from the
// URL path. Returns 404 if no incident with that ID exists.
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "incident id is required")
		return
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid incident id: expected UUID")
		return
	}

	incident, err := s.incidentStore.Get(r.Context(), id)
	if err != nil {
		slog.Error("incident get failed", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to get incident")
		return
	}

	if incident == nil {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}

	writeJSON(w, http.StatusOK, incident)
}

// handleInjectEvent accepts a raw JSON event via POST and publishes it to NATS
// for processing by the normal pipeline. This allows manual testing and
// integration with systems that prefer HTTP over NATS.
func (s *Server) handleInjectEvent(w http.ResponseWriter, r *http.Request) {
	var event eventschema.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Fill in defaults if the caller omitted them.
	if event.EventID == uuid.Nil {
		event.EventID = uuid.Must(uuid.NewV7())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if err := eventschema.ValidateEvent(&event); err != nil {
		writeError(w, http.StatusBadRequest, "validation failed: "+err.Error())
		return
	}

	if err := s.eventBus.Emit(r.Context(), event); err != nil {
		slog.Error("failed to publish event", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to publish event")
		return
	}

	slog.Info("event injected via API", "event_id", event.EventID, "signal_class", event.SignalClass)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":   "accepted",
		"event_id": event.EventID.String(),
	})
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
