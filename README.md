# Security Brain

AI-powered intrusion detection and prevention system for Kubernetes infrastructure.

## What Is This

Security Brain is a security decision fabric for AI infrastructure. It ingests security events from heterogeneous sensors (Falco, CI scanners, custom probes), correlates them through a multi-stage pipeline, evaluates policy, and executes automated response playbooks -- all while maintaining a complete audit trail.

## Architecture

The system follows a single-core-binary + plugin-adapter model:

- **Control Plane** (`cmd/control-plane`): The central decision engine. Runs the ingest, normalize, correlate, policy-evaluate, playbook-execute, and audit pipeline. Exposes an operator API on HTTP.
- **Sensor Adapters** (`cmd/adapter-falco`, `cmd/adapter-ci`): Lightweight binaries that translate vendor-specific alert formats into the unified `eventschema.Event` and publish them to the NATS event bus.
- **Enforcer Adapters** (`cmd/enforcer-k8s`, `cmd/enforcer-istio`): Subscribe to enforcement actions from the control plane and apply them to the target infrastructure (Kubernetes API, Istio service mesh).

Communication between components uses NATS subjects defined in `internal/transport/subjects.go`. Audit records are persisted to PostgreSQL.

## Prerequisites

- Go 1.24 or later
- Docker (for container builds)
- A running NATS server (for event bus)
- A running PostgreSQL instance (for audit storage)
- kubectl and Helm 3 (for Kubernetes deployment)

## Quick Start

### Build

```bash
# Build the control plane
go build -o bin/control-plane ./cmd/control-plane

# Build an adapter (e.g., Falco adapter)
go build -o bin/adapter-falco ./cmd/adapter-falco

# Build Docker images
docker build -t security-brain:latest .
docker build --build-arg BINARY_NAME=adapter-falco -f Dockerfile.adapter -t adapter-falco:latest .
```

### Run Locally

```bash
# Set environment variables (or use defaults)
export NATS_URL=nats://localhost:4222
export POSTGRES_DSN=postgres://secbrain:secbrain@localhost:5432/secbrain?sslmode=disable
export POLICY_DIR=/etc/security-brain/policies
export PLAYBOOKS_DIR=./playbooks
export API_ADDR=:8080

# Run the control plane
./bin/control-plane
```

### Deploy to Kubernetes

```bash
# Create the namespace
kubectl apply -f deploy/k8s/namespace.yaml

# Install with Helm
helm install security-brain deploy/helm/security-brain -n security-brain
```

## Project Structure

```
cmd/
  control-plane/       Main entry point for the decision engine
  adapter-falco/       Falco runtime alert adapter
  adapter-ci/          CI/CD pipeline scanner adapter
  enforcer-k8s/        Kubernetes enforcement adapter
  enforcer-istio/      Istio service mesh enforcement adapter
internal/
  api/                 HTTP operator API (health, audit, playbooks)
  audit/               Audit trail storage and query
  correlate/           Event correlation and classification
  domain/              Core configuration and domain types
  ingest/              Event ingestion from NATS
  normalize/           Event normalization pipeline
  playbooks/           Playbook registry and execution engine
  policy/              Policy loading and evaluation
  transport/           NATS event bus abstraction
pkg/
  eventschema/         Shared event, incident, and audit record types
  pluginapi/           Sensor, enforcer, and recovery plugin interfaces
  policytypes/         Action types, enforcement actions, policy matrix
deploy/
  helm/security-brain/ Helm chart for Kubernetes deployment
  k8s/                 Raw Kubernetes manifests (namespace)
playbooks/             Playbook YAML definitions (isolate, kill-replace)
docs/                  Architecture and implementation documentation
```

## Reference

See [Implementation Plan IDS-IPS 01.md](../Implementation%20Plan%20IDS-IPS%2001.md) for the full phased implementation plan and design rationale.
