<p align="center">
  <h1 align="center">SecureManx AI</h1>
  <p align="center">
    <strong>Automated security decision fabric for AI infrastructure</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="#components">Components</a> &middot;
    <a href="#configuration">Configuration</a> &middot;
    <a href="#contributing">Contributing</a>
  </p>
</p>

---

SecureManx AI is an agent-orchestrated intrusion detection and prevention system purpose-built for AI-native infrastructure. It monitors model gateways, agent runtimes, Kubernetes workloads, CI/CD pipelines, and cloud VMs &mdash; correlates weak signals into actionable incidents &mdash; and executes pre-approved containment at machine speed.

**What it does:**

- **Detect** &mdash; sensors watch for prompt injection, credential theft, lateral movement, supply chain tampering, and privilege escalation across five telemetry planes
- **Correlate** &mdash; a three-stage pipeline combines weak signals from the same workload into compound incidents with threat hypotheses
- **Decide** &mdash; OPA/Rego policy maps confidence &times; asset criticality to pre-approved actions, separating detection confidence from response authority
- **Contain** &mdash; enforcement adapters execute playbooks: kill pods, isolate containers, reroute traffic, freeze pipelines, revoke credentials
- **Prove** &mdash; every detection, decision, and action is logged to an immutable PostgreSQL audit trail

**What it is not:** a firewall, an antivirus, or a log aggregator. It is a *decision and response fabric* that sits above your existing infrastructure and orchestrates containment when your AI workloads are compromised.

## Quick Start

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

### Run everything locally

```bash
# Clone the repo
git clone https://github.com/TylerRoche-git/SecureManx-AI.git
cd SecureManx-AI

# Start NATS + Postgres + control plane in containers
docker compose up --build

# Open the dashboard
# http://localhost:8080
```

### Or run the binary directly

```bash
# Start infrastructure only
docker compose up -d nats postgres

# Build and run the control plane
./scripts/run-local.sh

# Open the dashboard at http://localhost:8080
```

### Verify it works

```bash
# Inject a critical test event
./scripts/inject-test-event.sh critical

# Check for incidents
curl http://localhost:8080/api/v1/incidents

# Or run the full smoke test
./scripts/smoke-test.sh
```

## Architecture

```
    Sensors              Control Plane              Enforcers
    ───────              ─────────────              ─────────

 ┌──────────┐     ┌─────────────────────────┐    ┌──────────────┐
 │  Falco   │     │  Ingest                 │    │  Kubernetes  │
 │  CI/CD   │     │  Normalize              │    │  Istio       │
 │  Network ├─NATS─▶ Pre-filter (Stage 1)   ├NATS─▶ Docker      │
 │  Identity│     │  Correlate  (Stage 2)   │    │  VM          │
 │  Gateway │     │  Policy     (Stage 3)   │    │  Process     │
 └──────────┘     │  Playbooks              │    └──────────────┘
                  │  Audit                  │
                  │  ────────               │
                  │  Sentinel (self-check)  │
                  │  Dashboard (:8080)      │
                  └─────────────────────────┘
                              │
                     ┌────────┴────────┐
                     │    Watchdog     │
                     │ (external guard)│
                     └─────────────────┘
```

### Three-stage decision pipeline

The core architectural decision: **AI reasoning is sandwiched between two deterministic layers**.

| Stage | Type | Role |
|-------|------|------|
| **Stage 1: Pre-filter** | Deterministic | Rules, thresholds, signatures. Drops noise, passes threats. Fast. |
| **Stage 2: Classifier** | Intelligent | Sliding-window correlation, intent estimation, blast-radius scoring. Produces *incidents* from multiple *events*. |
| **Stage 3: Policy gate** | Deterministic | OPA/Rego. Maps classification to allowed actions. **Only this stage can authorise enforcement.** |

Stage 2 can say *"this looks like credential exfiltration with 80% confidence."*
But the actual kill only happens because Stage 3 says *"confidence > 0.7 on this asset class permits kill_replace."*

This prevents free-range AI security automation.

### Self-protection

The control plane is itself a high-value target. Three defence layers:

| Layer | Component | Mechanism |
|-------|-----------|-----------|
| Internal | Sentinel | Hashes its own binary + policy files every 30s. Detects tampering and emits a critical event into its own pipeline. |
| External | Watchdog | Separate minimal binary. Checks health endpoint + binary hash. Kills the control plane if compromised. |
| Infrastructure | Deadman switch | If heartbeats stop, your K8s liveness probe or cloud function rebuilds from trusted image. |

## Components

### 12 deployable binaries

| Binary | Type | What it does |
|--------|------|-------------|
| `control-plane` | Core | Full pipeline: ingest, correlate, policy, playbooks, audit, API, dashboard, sentinel |
| `adapter-falco` | Sensor | Falco runtime events (gRPC + HTTP webhook) |
| `adapter-ci` | Sensor | GitHub Actions / GitLab CI webhooks with HMAC verification |
| `adapter-network` | Sensor | Flow log analysis: beaconing, exfiltration, port scan, lateral movement |
| `adapter-identity` | Sensor | Kubernetes audit log: secret access, privilege escalation, pod exec |
| `adapter-gateway` | Sensor | AI model gateway: prompt injection, abnormal tool use, data egress |
| `enforcer-k8s` | Enforcer | Kubernetes: NetworkPolicy, pod kill, node cordon, secret rotation |
| `enforcer-istio` | Enforcer | Istio: VirtualService fault injection, circuit breaking, Sidecar egress |
| `enforcer-docker` | Enforcer | Docker: quarantine network, container kill/replace, pause, credential strip |
| `enforcer-vm` | Enforcer | Cloud VMs: security group, instance stop/replace, quarantine VPC |
| `enforcer-process` | Enforcer | Bare metal: iptables, cgroups, SIGTERM/SIGKILL, cron freeze |
| `watchdog` | Integrity | External monitor: kills control plane if binary is tampered or unresponsive |

### You run what you need

Minimum deployment: `control-plane` + one sensor + one enforcer.

The control plane is always required. Choose sensors for your telemetry sources and enforcers for your infrastructure. Everything else is optional.

## Operator Dashboard

The control plane serves a web dashboard at `http://localhost:8080/`:

- **Dashboard** &mdash; system health, incident stats, recent incidents (auto-refreshing)
- **Incidents** &mdash; full table with expandable detail panels, status badges, policy decisions
- **Audit Trail** &mdash; filterable by phase (detection, correlation, decision, enforcement, recovery)
- **Playbooks** &mdash; all 6 playbooks with expandable step details
- **Test Events** &mdash; one-click injection of critical/medium/low test events

The dashboard is embedded in the Go binary. No separate frontend server, no npm, no CDN. Works air-gapped.

## Playbooks

Six pre-built response playbooks:

| Playbook | Trigger | Steps |
|----------|---------|-------|
| `isolate` | Correlation threshold crossed | NetworkPolicy deny &rarr; label pod &rarr; capture state &rarr; notify |
| `kill-replace` | High confidence, replaceable workload | Isolate &rarr; capture &rarr; cordon &rarr; delete pod &rarr; verify replacement &rarr; health check |
| `rebuild-trusted` | Integrity failure | Find trusted image &rarr; verify signature &rarr; deploy &rarr; health check &rarr; restore traffic |
| `revoke-credentials` | Credential access or lateral movement | Identify creds &rarr; rotate &rarr; invalidate sessions &rarr; restart dependents &rarr; monitor |
| `reroute-traffic` | Service degradation during containment | Shift traffic &rarr; circuit breaker &rarr; degraded mode &rarr; monitor new path |
| `freeze-pipeline` | Supply chain anomaly | Halt pipelines &rarr; quarantine artefacts &rarr; integrity scan &rarr; block promotion &rarr; notify |

Custom playbooks: add a YAML file to the `playbooks/` directory.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `POSTGRES_DSN` | `postgres://secbrain:secbrain@localhost:5432/secbrain?sslmode=disable` | PostgreSQL connection string |
| `POLICY_DIR` | `/etc/security-brain/policies` | Directory containing Rego policy files |
| `PLAYBOOKS_DIR` | `/etc/security-brain/playbooks` | Directory containing playbook YAML files |
| `API_ADDR` | `:8080` | API and dashboard listen address |
| `CORRELATION_WINDOW` | `5m` | Sliding window duration for event correlation |
| `SLACK_WEBHOOK_URL` | *(empty)* | Enables Slack alerting |
| `SLACK_CHANNEL` | `#security-alerts` | Slack channel for alerts |
| `PAGERDUTY_ROUTING_KEY` | *(empty)* | Enables PagerDuty alerting |
| `ALERT_WEBHOOK_URL` | *(empty)* | Enables generic webhook alerting |
| `WEBHOOK_SECRET` | *(empty)* | HMAC secret for CI adapter webhook verification |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/healthz` | Health check (includes sentinel status) |
| `GET` | `/api/v1/incidents` | List incidents (query: `status`, `min_confidence`, `since`, `until`, `limit`) |
| `GET` | `/api/v1/incidents/{id}` | Get incident by ID |
| `GET` | `/api/v1/audit` | List audit records (query: `phase`, `since`, `until`, `limit`) |
| `GET` | `/api/v1/playbooks` | List all playbooks |
| `GET` | `/api/v1/playbooks/{id}` | Get playbook by ID |
| `POST` | `/api/v1/events` | Inject a raw event into the pipeline |
| `GET` | `/` | Operator dashboard |

## Project Structure

```
SecureManx-AI/
├── cmd/
│   ├── control-plane/       Core decision engine
│   ├── adapter-falco/       Falco runtime sensor
│   ├── adapter-ci/          CI/CD webhook sensor
│   ├── adapter-network/     Network flow analyzer
│   ├── adapter-identity/    K8s audit log sensor
│   ├── adapter-gateway/     AI model gateway sensor
│   ├── enforcer-k8s/        Kubernetes enforcer
│   ├── enforcer-istio/      Istio service mesh enforcer
│   ├── enforcer-docker/     Docker container enforcer
│   ├── enforcer-vm/         Cloud VM enforcer
│   ├── enforcer-process/    Bare metal process enforcer
│   └── watchdog/            External integrity monitor
├── internal/
│   ├── api/                 HTTP API + embedded dashboard
│   ├── alerting/            Slack, PagerDuty, webhook sinks
│   ├── audit/               PostgreSQL audit trail
│   ├── correlate/           Three-stage correlation engine
│   ├── domain/              Configuration and domain types
│   ├── incidents/           PostgreSQL incident storage
│   ├── ingest/              Event ingestion from NATS
│   ├── normalize/           Event normalization
│   ├── playbooks/           Playbook registry and executor
│   ├── policy/              OPA/Rego policy evaluation
│   ├── sentinel/            Self-integrity monitoring
│   └── transport/           NATS JetStream client
├── pkg/
│   ├── eventschema/         Event, Incident, AuditRecord types
│   ├── pluginapi/           Sensor, Enforcer, Recovery interfaces
│   └── policytypes/         Action types and policy matrix
├── policies/                OPA/Rego policy files
├── playbooks/               Playbook YAML definitions
├── deploy/
│   ├── helm/                Helm chart
│   └── k8s/                 Raw Kubernetes manifests
├── scripts/                 Run, inject, and smoke test scripts
├── test/integration/        End-to-end pipeline tests
├── docker-compose.yaml      Local development stack
├── Dockerfile               Control plane container
└── Dockerfile.adapter       Adapter container (parameterised)
```

## Building

```bash
# Build all binaries
go build ./...

# Build a specific binary
CGO_ENABLED=0 go build -o bin/control-plane ./cmd/control-plane

# Run tests
go test ./... -count=1

# Run integration tests
go test ./test/integration/... -tags=integration -count=1

# Docker images
docker build -t securemanx:latest .
docker build --build-arg BINARY_NAME=enforcer-k8s -f Dockerfile.adapter -t securemanx-enforcer-k8s:latest .
```

## Deployment

### Docker Compose (development)

```bash
docker compose up --build
```

### Kubernetes (production)

```bash
kubectl apply -f deploy/k8s/namespace.yaml
helm install securemanx deploy/helm/security-brain -n security-brain
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull request process.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
