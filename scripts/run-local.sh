#!/usr/bin/env bash
# Start local infrastructure and run the control plane.
set -euo pipefail

echo "Starting NATS and PostgreSQL..."
docker compose up -d

echo "Waiting for services..."
sleep 3

echo "Starting control plane..."
export NATS_URL=nats://localhost:4222
export POSTGRES_DSN="postgres://secbrain:secbrain@localhost:5432/secbrain?sslmode=disable"
export POLICY_DIR=./policies
export PLAYBOOKS_DIR=./playbooks
export API_ADDR=:8080

go run ./cmd/control-plane
