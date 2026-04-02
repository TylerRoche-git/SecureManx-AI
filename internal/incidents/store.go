// Package incidents provides PostgreSQL-backed storage for security incidents.
package incidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// createTableSQL is the DDL executed on store initialisation.
const createTableSQL = `CREATE TABLE IF NOT EXISTS incidents (
	incident_id          UUID PRIMARY KEY,
	timestamp            TIMESTAMPTZ NOT NULL,
	contributing_events  JSONB NOT NULL DEFAULT '[]',
	threat_hypothesis    TEXT NOT NULL DEFAULT '',
	confidence_score     FLOAT8 NOT NULL DEFAULT 0,
	asset_criticality    TEXT NOT NULL DEFAULT '',
	recommended_playbook TEXT NOT NULL DEFAULT '',
	policy_decision      JSONB NOT NULL DEFAULT '{}',
	execution_status     TEXT NOT NULL DEFAULT 'pending'
)`

// IncidentFilter specifies criteria for querying incidents.
type IncidentFilter struct {
	Status           eventschema.ExecutionStatus
	MinConfidence    float64
	AssetCriticality eventschema.Severity
	Since            time.Time
	Until            time.Time
	Limit            int
}

// Store persists incidents in PostgreSQL using a connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store backed by the PostgreSQL instance at dsn.
// It creates the incidents table if it does not already exist.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}

	if _, execErr := pool.Exec(ctx, createTableSQL); execErr != nil {
		pool.Close()
		return nil, fmt.Errorf("create incidents table: %w", execErr)
	}

	return &Store{pool: pool}, nil
}

// Insert persists a single Incident, serialising nested structs to JSONB.
func (s *Store) Insert(ctx context.Context, incident *eventschema.Incident) error {
	contributingEvents, err := json.Marshal(incident.ContributingEvents)
	if err != nil {
		return fmt.Errorf("marshal contributing_events: %w", err)
	}

	policyDecision, err := json.Marshal(incident.PolicyDecision)
	if err != nil {
		return fmt.Errorf("marshal policy_decision: %w", err)
	}

	const insertSQL = `INSERT INTO incidents
		(incident_id, timestamp, contributing_events, threat_hypothesis,
		 confidence_score, asset_criticality, recommended_playbook,
		 policy_decision, execution_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = s.pool.Exec(ctx, insertSQL,
		incident.IncidentID,
		incident.Timestamp,
		contributingEvents,
		incident.ThreatHypothesis,
		incident.ConfidenceScore,
		string(incident.AssetCriticality),
		incident.RecommendedPlaybook,
		policyDecision,
		string(incident.ExecutionStatus),
	)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	return nil
}

// Get retrieves a single incident by its ID. It returns (nil, nil) if no
// incident with that ID exists, allowing the caller to distinguish "not found"
// from an actual error.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*eventschema.Incident, error) {
	const selectSQL = `SELECT incident_id, timestamp, contributing_events,
		threat_hypothesis, confidence_score, asset_criticality,
		recommended_playbook, policy_decision, execution_status
		FROM incidents WHERE incident_id = $1`

	var inc eventschema.Incident
	var assetCriticality, executionStatus string
	var contributingEventsRaw, policyDecisionRaw []byte

	err := s.pool.QueryRow(ctx, selectSQL, id).Scan(
		&inc.IncidentID,
		&inc.Timestamp,
		&contributingEventsRaw,
		&inc.ThreatHypothesis,
		&inc.ConfidenceScore,
		&assetCriticality,
		&inc.RecommendedPlaybook,
		&policyDecisionRaw,
		&executionStatus,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get incident: %w", err)
	}

	inc.AssetCriticality = eventschema.Severity(assetCriticality)
	inc.ExecutionStatus = eventschema.ExecutionStatus(executionStatus)

	if unmarshalErr := json.Unmarshal(contributingEventsRaw, &inc.ContributingEvents); unmarshalErr != nil {
		return nil, fmt.Errorf("unmarshal contributing_events: %w", unmarshalErr)
	}

	if unmarshalErr := json.Unmarshal(policyDecisionRaw, &inc.PolicyDecision); unmarshalErr != nil {
		return nil, fmt.Errorf("unmarshal policy_decision: %w", unmarshalErr)
	}

	return &inc, nil
}

// Update modifies the execution_status, policy_decision, and recommended_playbook
// of an existing incident identified by its IncidentID.
func (s *Store) Update(ctx context.Context, incident *eventschema.Incident) error {
	policyDecision, err := json.Marshal(incident.PolicyDecision)
	if err != nil {
		return fmt.Errorf("marshal policy_decision: %w", err)
	}

	const updateSQL = `UPDATE incidents
		SET execution_status = $1, policy_decision = $2, recommended_playbook = $3
		WHERE incident_id = $4`

	_, err = s.pool.Exec(ctx, updateSQL,
		string(incident.ExecutionStatus),
		policyDecision,
		incident.RecommendedPlaybook,
		incident.IncidentID,
	)
	if err != nil {
		return fmt.Errorf("update incident: %w", err)
	}
	return nil
}

// Query retrieves incidents matching the provided filter. Fields that are
// zero-valued are ignored. If no limit is specified the default is 100.
func (s *Store) Query(ctx context.Context, filter IncidentFilter) ([]eventschema.Incident, error) {
	var clauses []string
	var args []any
	argIdx := 1

	if filter.Status != "" {
		clauses = append(clauses, fmt.Sprintf("execution_status = $%d", argIdx))
		args = append(args, string(filter.Status))
		argIdx++
	}

	if filter.MinConfidence > 0 {
		clauses = append(clauses, fmt.Sprintf("confidence_score >= $%d", argIdx))
		args = append(args, filter.MinConfidence)
		argIdx++
	}

	if filter.AssetCriticality != "" {
		clauses = append(clauses, fmt.Sprintf("asset_criticality = $%d", argIdx))
		args = append(args, string(filter.AssetCriticality))
		argIdx++
	}

	if !filter.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, filter.Since)
		argIdx++
	}

	if !filter.Until.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, filter.Until)
		argIdx++
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT incident_id, timestamp, contributing_events,
		threat_hypothesis, confidence_score, asset_criticality,
		recommended_playbook, policy_decision, execution_status
		FROM incidents`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query incidents: %w", err)
	}
	defer rows.Close()

	var incidents []eventschema.Incident
	for rows.Next() {
		var inc eventschema.Incident
		var assetCriticality, executionStatus string
		var contributingEventsRaw, policyDecisionRaw []byte

		if scanErr := rows.Scan(
			&inc.IncidentID,
			&inc.Timestamp,
			&contributingEventsRaw,
			&inc.ThreatHypothesis,
			&inc.ConfidenceScore,
			&assetCriticality,
			&inc.RecommendedPlaybook,
			&policyDecisionRaw,
			&executionStatus,
		); scanErr != nil {
			return nil, fmt.Errorf("scan incident: %w", scanErr)
		}

		inc.AssetCriticality = eventschema.Severity(assetCriticality)
		inc.ExecutionStatus = eventschema.ExecutionStatus(executionStatus)

		if unmarshalErr := json.Unmarshal(contributingEventsRaw, &inc.ContributingEvents); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal contributing_events: %w", unmarshalErr)
		}

		if unmarshalErr := json.Unmarshal(policyDecisionRaw, &inc.PolicyDecision); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal policy_decision: %w", unmarshalErr)
		}

		incidents = append(incidents, inc)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate incidents: %w", rowsErr)
	}

	if incidents == nil {
		incidents = make([]eventschema.Incident, 0)
	}

	return incidents, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() {
	s.pool.Close()
}
