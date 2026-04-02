package playbooks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/internal/transport"
	"github.com/security-brain/security-brain/pkg/eventschema"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// AuditWriter is the interface the executor needs for audit logging.
// It is satisfied by *audit.Writer without requiring a direct import of the
// audit package (though importing audit is also acceptable since audit does
// not import playbooks).
type AuditWriter interface {
	RecordEnforcement(ctx context.Context, actionID uuid.UUID, action policytypes.ActionType, targets []string, success bool) error
}

// Executor runs playbook steps against security incidents, publishing
// enforcement actions to the event bus and recording each step in the audit
// trail.
type Executor struct {
	registry *Registry
	bus      *transport.EventBus
	auditor  AuditWriter
}

// NewExecutor creates an Executor wired to the given registry, event bus, and
// audit writer.
func NewExecutor(reg *Registry, bus *transport.EventBus, auditor AuditWriter) *Executor {
	return &Executor{
		registry: reg,
		bus:      bus,
		auditor:  auditor,
	}
}

// Execute runs the playbook associated with the incident's RecommendedPlaybook
// field. If no matching playbook is found, it defaults to "isolate". Each step
// is published as an EnforcementAction on the event bus and recorded via the
// audit writer.
func (e *Executor) Execute(ctx context.Context, incident *eventschema.Incident) error {
	playbookID := incident.RecommendedPlaybook
	if playbookID == "" {
		playbookID = "isolate"
	}

	pb, ok := e.registry.Get(playbookID)
	if !ok {
		slog.Warn("playbook not found, falling back to isolate",
			"requested", playbookID,
			"incident_id", incident.IncidentID,
		)
		playbookID = "isolate"
		pb, ok = e.registry.Get(playbookID)
		if !ok {
			return fmt.Errorf("default playbook 'isolate' not found in registry")
		}
	}

	slog.Info("executing playbook",
		"playbook_id", pb.ID,
		"playbook_name", pb.Name,
		"incident_id", incident.IncidentID,
		"steps", len(pb.Steps),
	)

	for i, step := range pb.Steps {
		stepTimeout := parseTimeout(step.Timeout)

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)

		actionType := policytypes.ActionType(step.Action)
		targets := []string{incident.IncidentID.String()}

		action := policytypes.NewEnforcementAction(actionType, incident.IncidentID, targets)
		action.PlaybookID = pb.ID

		data, err := json.Marshal(action)
		if err != nil {
			cancel()
			return fmt.Errorf("marshal enforcement action for step %d (%s): %w", i, step.Name, err)
		}

		if pubErr := e.bus.PublishEnforcementAction(stepCtx, data); pubErr != nil {
			cancel()
			recordErr := e.auditor.RecordEnforcement(ctx, action.ActionID, actionType, targets, false)
			if recordErr != nil {
				slog.Error("failed to record enforcement failure",
					"step", step.Name,
					"error", recordErr,
				)
			}
			return fmt.Errorf("publish enforcement action for step %d (%s): %w", i, step.Name, pubErr)
		}

		recordErr := e.auditor.RecordEnforcement(ctx, action.ActionID, actionType, targets, true)
		if recordErr != nil {
			slog.Error("failed to record enforcement success",
				"step", step.Name,
				"error", recordErr,
			)
		}

		slog.Info("playbook step executed",
			"playbook_id", pb.ID,
			"step_index", i,
			"step_name", step.Name,
			"action", step.Action,
			"timeout", stepTimeout,
			"action_id", action.ActionID,
		)

		cancel()
	}

	slog.Info("playbook execution complete",
		"playbook_id", pb.ID,
		"incident_id", incident.IncidentID,
	)

	return nil
}

// Rollback logs a rollback request for the given incident. Full rollback
// execution (reversing enforcement actions) is planned for Phase 4.
func (e *Executor) Rollback(_ context.Context, incidentID uuid.UUID) error {
	slog.Info("rollback requested",
		"incident_id", incidentID,
		"status", "logged-only",
		"note", "full rollback execution is planned for Phase 4",
	)
	return nil
}

// parseTimeout parses a Go duration string (e.g. "30s", "1m"). If the string
// is empty or invalid, it returns a 30-second default.
func parseTimeout(s string) time.Duration {
	if s == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 30 * time.Second
	}
	return d
}
