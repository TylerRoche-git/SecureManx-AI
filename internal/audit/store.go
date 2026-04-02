// Package audit provides PostgreSQL-backed storage and high-level writer
// facilities for immutable audit records.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-brain/security-brain/pkg/eventschema"
)

// createTableSQL is the DDL executed on store initialisation.
const createTableSQL = `CREATE TABLE IF NOT EXISTS audit_records (
	audit_id       UUID PRIMARY KEY,
	timestamp      TIMESTAMPTZ NOT NULL,
	phase          TEXT NOT NULL,
	event_ids      JSONB NOT NULL DEFAULT '[]',
	actor          TEXT NOT NULL,
	action_taken   TEXT NOT NULL DEFAULT '',
	policy_ref     TEXT NOT NULL DEFAULT '',
	inputs         JSONB NOT NULL DEFAULT '{}',
	outputs        JSONB NOT NULL DEFAULT '{}',
	rationale      TEXT NOT NULL DEFAULT '',
	evidence_refs  JSONB NOT NULL DEFAULT '[]',
	reversibility  JSONB NOT NULL DEFAULT '{}'
)`

// AuditFilter specifies criteria for querying audit records.
type AuditFilter struct {
	Phase    eventschema.AuditPhase
	Since    time.Time
	Until    time.Time
	EventIDs []uuid.UUID
	Limit    int
}

// Store persists audit records in PostgreSQL using a connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store backed by the PostgreSQL instance at dsn.
// It creates the audit_records table if it does not already exist.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}

	if _, execErr := pool.Exec(ctx, createTableSQL); execErr != nil {
		pool.Close()
		return nil, fmt.Errorf("create audit_records table: %w", execErr)
	}

	return &Store{pool: pool}, nil
}

// Insert persists a single AuditRecord, serialising nested structs to JSONB.
func (s *Store) Insert(ctx context.Context, record *eventschema.AuditRecord) error {
	eventIDs, err := json.Marshal(record.EventIDs)
	if err != nil {
		return fmt.Errorf("marshal event_ids: %w", err)
	}

	inputs, err := json.Marshal(record.Inputs)
	if err != nil {
		return fmt.Errorf("marshal inputs: %w", err)
	}

	outputs, err := json.Marshal(record.Outputs)
	if err != nil {
		return fmt.Errorf("marshal outputs: %w", err)
	}

	evidenceRefs, err := json.Marshal(record.EvidenceRefs)
	if err != nil {
		return fmt.Errorf("marshal evidence_refs: %w", err)
	}

	reversibility, err := json.Marshal(record.Reversibility)
	if err != nil {
		return fmt.Errorf("marshal reversibility: %w", err)
	}

	const insertSQL = `INSERT INTO audit_records
		(audit_id, timestamp, phase, event_ids, actor, action_taken, policy_ref,
		 inputs, outputs, rationale, evidence_refs, reversibility)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err = s.pool.Exec(ctx, insertSQL,
		record.AuditID,
		record.Timestamp,
		string(record.Phase),
		eventIDs,
		string(record.Actor),
		record.ActionTaken,
		record.PolicyRef,
		inputs,
		outputs,
		record.Rationale,
		evidenceRefs,
		reversibility,
	)
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

// Query retrieves audit records matching the provided filter. Fields that are
// zero-valued are ignored. If no limit is specified the default is 100.
func (s *Store) Query(ctx context.Context, filter AuditFilter) ([]eventschema.AuditRecord, error) {
	var clauses []string
	var args []any
	argIdx := 1

	if filter.Phase != "" {
		clauses = append(clauses, fmt.Sprintf("phase = $%d", argIdx))
		args = append(args, string(filter.Phase))
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

	if len(filter.EventIDs) > 0 {
		eventIDsJSON, err := json.Marshal(filter.EventIDs)
		if err != nil {
			return nil, fmt.Errorf("marshal filter event_ids: %w", err)
		}
		clauses = append(clauses, fmt.Sprintf("event_ids @> $%d::jsonb", argIdx))
		args = append(args, string(eventIDsJSON))
		argIdx++
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query := "SELECT audit_id, timestamp, phase, event_ids, actor, action_taken, policy_ref, inputs, outputs, rationale, evidence_refs, reversibility FROM audit_records"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer rows.Close()

	var records []eventschema.AuditRecord
	for rows.Next() {
		var rec eventschema.AuditRecord
		var phase, actor string
		var eventIDsRaw, inputsRaw, outputsRaw, evidenceRefsRaw, reversibilityRaw []byte

		if scanErr := rows.Scan(
			&rec.AuditID,
			&rec.Timestamp,
			&phase,
			&eventIDsRaw,
			&actor,
			&rec.ActionTaken,
			&rec.PolicyRef,
			&inputsRaw,
			&outputsRaw,
			&rec.Rationale,
			&evidenceRefsRaw,
			&reversibilityRaw,
		); scanErr != nil {
			return nil, fmt.Errorf("scan audit record: %w", scanErr)
		}

		rec.Phase = eventschema.AuditPhase(phase)
		rec.Actor = eventschema.AuditActor(actor)

		if unmarshalErr := json.Unmarshal(eventIDsRaw, &rec.EventIDs); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal event_ids: %w", unmarshalErr)
		}
		if unmarshalErr := json.Unmarshal(inputsRaw, &rec.Inputs); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal inputs: %w", unmarshalErr)
		}
		if unmarshalErr := json.Unmarshal(outputsRaw, &rec.Outputs); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal outputs: %w", unmarshalErr)
		}
		if unmarshalErr := json.Unmarshal(evidenceRefsRaw, &rec.EvidenceRefs); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal evidence_refs: %w", unmarshalErr)
		}
		if unmarshalErr := json.Unmarshal(reversibilityRaw, &rec.Reversibility); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshal reversibility: %w", unmarshalErr)
		}

		records = append(records, rec)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate audit records: %w", rowsErr)
	}

	if records == nil {
		records = make([]eventschema.AuditRecord, 0)
	}

	return records, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() {
	s.pool.Close()
}
