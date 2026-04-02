package pluginapi

import (
	"context"

	"github.com/google/uuid"
	"github.com/security-brain/security-brain/pkg/policytypes"
)

// Enforcer executes containment and remediation actions against infrastructure.
type Enforcer interface {
	// Name returns a human-readable identifier for this enforcer.
	Name() string

	// Capabilities returns the action types this enforcer can execute.
	Capabilities() []policytypes.ActionType

	// Execute performs the specified enforcement action.
	Execute(ctx context.Context, action policytypes.EnforcementAction) error

	// Rollback reverses a previously executed action.
	Rollback(ctx context.Context, actionID uuid.UUID) error

	// HealthCheck returns nil if the enforcer is operating normally.
	HealthCheck(ctx context.Context) error
}
