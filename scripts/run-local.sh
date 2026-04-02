#!/usr/bin/env bash
# Start local infrastructure and run the control plane.
# Usage: ./scripts/run-local.sh
#
# Prerequisites: Docker Desktop running
# Starts: NATS (JetStream) + PostgreSQL via Docker Compose
# Then:   Builds and runs the control plane binary
#
# To stop: Ctrl+C, then: docker compose down
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

echo "Starting NATS and PostgreSQL..."
docker compose up -d nats postgres

echo "Waiting for services to be healthy..."
for i in $(seq 1 30); do
  if docker compose ps --format json | grep -q '"healthy"' 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "Building control plane..."
go build -o bin/control-plane ./cmd/control-plane

echo "Starting control plane..."
export NATS_URL=nats://localhost:4222
export POSTGRES_DSN="postgres://secbrain:secbrain@localhost:5432/secbrain?sslmode=disable"
export POLICY_DIR="$PROJECT_DIR/policies"
export PLAYBOOKS_DIR="$PROJECT_DIR/playbooks"
export API_ADDR=:8080

echo ""
echo "  API:       http://localhost:8080/healthz"
echo "  Events:    POST http://localhost:8080/api/v1/events"
echo "  Incidents: GET  http://localhost:8080/api/v1/incidents"
echo "  Audit:     GET  http://localhost:8080/api/v1/audit"
echo "  Playbooks: GET  http://localhost:8080/api/v1/playbooks"
echo ""

exec ./bin/control-plane
