# Contributing to SecureManx AI

Thank you for your interest in contributing. This document covers the development setup, coding standards, and pull request process.

## Development Setup

### Prerequisites

- Go 1.24 or later
- Docker and Docker Compose
- Git

### Getting started

```bash
git clone https://github.com/TylerRoche-git/SecureManx-AI.git
cd SecureManx-AI

# Start local infrastructure
docker compose up -d nats postgres

# Build everything
go build ./...

# Run tests
go test ./... -count=1

# Run the control plane
./scripts/run-local.sh
```

### Running integration tests

```bash
go test ./test/integration/... -tags=integration -count=1
```

## Project Layout

- `cmd/` &mdash; each subdirectory is a deployable binary
- `internal/` &mdash; packages private to this module (not importable by other projects)
- `pkg/` &mdash; public contracts that adapters import (event schema, plugin interfaces, policy types)
- `policies/` &mdash; OPA/Rego policy files
- `playbooks/` &mdash; response playbook YAML definitions

## Coding Standards

### Go

- Follow standard Go conventions (`go vet`, `gofmt`)
- Use `log/slog` for structured logging
- Use `encoding/json` and `net/http` from the standard library where possible
- No TODOs in committed code &mdash; implement it, stub it with a clear name, or file an issue
- Keep dependencies minimal &mdash; each new dependency should be justified
- Error messages should be lowercase and not end with punctuation

### Architecture

- The three-stage pipeline (pre-filter, classifier, policy gate) is a core invariant. Changes to it should be discussed in an issue first.
- Sensor and enforcer adapters communicate only via NATS. They must not import `internal/` packages.
- New adapters should follow the existing patterns in `cmd/adapter-*` or `cmd/enforcer-*`.

### Tests

- Unit tests go alongside the code (`foo_test.go` next to `foo.go`)
- Integration tests go in `test/integration/` with the `//go:build integration` tag
- Tests that require external infrastructure (NATS, Postgres) must be skipped when unavailable, not fail

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes with clear, atomic commits
3. Ensure `go build ./...` and `go test ./...` pass
4. Ensure `go vet ./...` reports no issues
5. Update documentation if you changed behaviour
6. Open a pull request with a clear description of what and why

### Commit messages

- Use imperative mood ("Add feature" not "Added feature")
- First line under 72 characters
- Reference issues where applicable (`Fixes #123`)

## Adding a New Sensor Adapter

1. Create `cmd/adapter-yourname/main.go`
2. Connect to NATS and create an `EventBus`
3. Accept input (HTTP webhook, gRPC, file, etc.)
4. Map vendor-specific events to `eventschema.Event`
5. Publish via `EventBus.Emit()`
6. Add the binary to `.github/workflows/ci.yaml` build matrix
7. Add the binary to `Dockerfile.adapter` build args documentation
8. Update `README.md` components table

## Adding a New Enforcer Adapter

1. Create `cmd/enforcer-yourname/main.go`
2. Connect to NATS and subscribe to `security.enforcement.actions`
3. Implement action dispatch based on `policytypes.ActionType`
4. Ack/nak NATS messages based on success/failure
5. Follow the same CI and documentation steps as sensors

## Reporting Bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Go version, OS, and relevant environment details
