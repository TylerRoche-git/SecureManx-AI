# Changelog

All notable changes to SecureManx AI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-02

### Added

#### Core
- Control plane binary with full detection-to-response pipeline
- Three-stage correlation engine: deterministic pre-filter, sliding-window classifier, OPA/Rego policy gate
- Event and Incident schemas with JSON serialization and validation
- PostgreSQL-backed audit trail with append-only immutable records
- PostgreSQL-backed incident storage with CRUD and filtering
- Playbook executor with step-by-step execution and audit recording
- OPA/Rego policy evaluation with hardcoded matrix fallback
- Operator REST API with health, incidents, audit, playbooks, and event injection endpoints
- Embedded web dashboard (dark theme, auto-refresh, air-gapped) served at `/`
- NATS JetStream event transport with typed pub/sub
- Environment-variable-based configuration with sensible defaults

#### Sensors (5 detection planes)
- **Falco adapter**: dual-mode gRPC + HTTP webhook, Falco priority/rule mapping
- **CI/CD adapter**: GitHub Actions and GitLab CI webhook receiver with HMAC-SHA256 verification
- **Network adapter**: flow log analysis with beaconing, exfiltration, port scan, and lateral movement detection
- **Identity adapter**: Kubernetes audit log consumer detecting unusual secret access, privilege escalation, token creation, pod exec, policy bypass
- **Gateway adapter**: AI model gateway monitor with rule-based prompt injection detection (8 patterns), abnormal tool use, data egress, token anomaly

#### Enforcers (5 infrastructure targets)
- **Kubernetes**: NetworkPolicy creation, pod kill/replace, node cordon, service account token rotation via client-go
- **Istio**: VirtualService fault injection, DestinationRule circuit breaking, Sidecar egress restriction via dynamic client
- **Docker**: quarantine network isolation, container kill/replace with forensic rename, pause, credential stripping via Docker Engine API
- **VM**: cloud VM security group modification, instance stop/replace, quarantine VPC, credential revocation (dispatch-ready)
- **Process**: iptables isolation, cgroup freeze, SIGTERM/SIGKILL, service disable, cron removal (dispatch-ready)

#### Self-Integrity
- Sentinel: binary and policy hash verification every 30 seconds, behavioral canary injection, signed heartbeat publication
- Watchdog: external monitor binary that kills the control plane if binary is tampered or health checks fail

#### Alerting
- Multi-sink alert router with Slack webhook, PagerDuty Events API v2, and generic webhook sinks
- Alerts triggered on non-detect-only incidents with severity, title, incident ID, and action details

#### Playbooks
- `isolate`: network policy deny, pod labelling, state capture, operator notification
- `kill-replace`: isolate, cordon, delete pod, verify replacement, health check
- `rebuild-trusted`: image verification, deploy from trust registry, health check, traffic restoration
- `revoke-credentials`: secret rotation, session invalidation, dependent restart, monitoring
- `reroute-traffic`: VirtualService update, circuit breaker, degraded mode fallback
- `freeze-pipeline`: halt CI/CD, quarantine artefacts, integrity scan, block promotion

#### Infrastructure
- Docker Compose for local development (NATS JetStream + PostgreSQL + control plane + adapters)
- Helm chart for Kubernetes deployment
- Multi-stage Dockerfiles for control plane and adapter binaries
- GitHub Actions CI pipeline (lint, test with race detector, matrix build of all 12 binaries, Docker image builds)

#### Testing
- 187 unit and integration tests covering validation, policy matrix, pre-filter, classifier, normalizer, sentinel hashing, OPA evaluation, alerting sinks, Falco mapping, gateway detection, and end-to-end pipeline scenarios
- Smoke test script for end-to-end verification through real NATS and PostgreSQL
- Event injection script for manual testing

[0.1.0]: https://github.com/TylerRoche-git/SecureManx-AI/releases/tag/v0.1.0
