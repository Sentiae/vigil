# Vigil — Security & Infrastructure Intelligence Platform

**Vigil** is Sentiae's security intelligence platform. It provides real-time threat detection, vulnerability scanning, and compliance monitoring for cloud-native infrastructure.

## Architecture

Vigil consists of two components:

```
┌─────────────────────────────────────────────────────────────┐
│  CUSTOMER K8S CLUSTER              SENTIAE PLATFORM         │
│                                                             │
│  ┌──────────────┐         gRPC          ┌──────────────┐   │
│  │   vigil-     │ ────────────────────▶ │   vigil-     │   │
│  │   agent      │     (mTLS + TLS)      │   service    │   │
│  │   (DaemonSet)│                       │  (Control    │   │
│  │              │                       │   Plane)     │   │
│  │  • eBPF      │                       │              │   │
│  │  • Telemetry │                       │  • HTTP API  │   │
│  │  • Rules     │                       │  • Scanners  │   │
│  │  • Anomaly   │                       │  • Storage   │   │
│  └──────────────┘                       └──────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
vigil/
├── agent/                    # K8s DaemonSet (customer clusters)
│   ├── cmd/
│   │   ├── agent/            # eBPF telemetry collector
│   │   └── operator/         # Kubernetes operator
│   ├── internal/
│   │   ├── ebpf/             # eBPF programs
│   │   ├── monitor/          # TLS, DNS, K8s audit monitors
│   │   ├── runtime/          # Rule engine, anomaly detection
│   │   └── transport/        # gRPC client, WAL buffer
│   ├── k8s/                  # Kubernetes manifests
│   └── Dockerfile
│
├── service/                  # Control plane (Sentiae infra)
│   ├── cmd/
│   │   ├── server/           # HTTP + gRPC control plane
│   │   └── worker/           # Scanner worker
│   ├── internal/
│   │   ├── adapter/          # Handlers, repositories, scanners
│   │   ├── port/             # Hexagonal architecture ports
│   │   ├── usecase/          # Business logic
│   │   └── domain/           # Pure business models
│   ├── pkg/
│   │   ├── config/           # Configuration
│   │   ├── database/         # Database connections
│   │   ├── logger/           # Structured logging
│   │   ├── storage/          # S3/MinIO client
│   │   └── telemetry/        # OpenTelemetry + Prometheus
│   ├── migrations/           # Atlas SQL migrations
│   ├── Dockerfile
│   └── Dockerfile.worker
│
└── shared/                   # Shared code (single source of truth)
    ├── proto/vigil/v1/       # Agent↔Service gRPC contracts
    ├── events/               # CloudEvents type definitions
    ├── models/               # Shared domain models
    ├── version/              # Single version constant
    └── go.mod
```

## Quick Start

### Build Both Binaries
```bash
cd vigil
make build-all
```

### Run Tests
```bash
make test-all
```

### Build Docker Images
```bash
make docker-build-all
```

### Deploy Agent (Kubernetes)
```bash
kubectl apply -f agent/k8s/
```

### Run Service Locally
```bash
cd service
go run ./cmd/server
```

## Components

### Agent (vigil-agent)
Deployed as a Kubernetes DaemonSet on customer clusters. Collects:
- **eBPF telemetry** — Syscall monitoring (execve, openat, connect, etc.)
- **TLS inspection** — Certificate validation, cipher analysis
- **DNS monitoring** — Tunneling detection, DGA domain detection
- **K8s audit logs** — RBAC violations, privilege escalation
- **Anomaly detection** — Statistical baselines with z-score alerting

### Service (vigil-server + vigil-worker)
**Control Plane** (`vigil-server`):
- REST API (port 8080)
- gRPC server for agent communication (port 50054)
- Multi-store data layer (PostgreSQL, ClickHouse, Neo4j, Redis, MinIO)

**Scanner Worker** (`vigil-worker`):
- 11 independent security scanners
- Asynq-based task queue
- Bundled tools: Trivy, Semgrep, etc.

## Shared Code

The `shared/` directory contains code used by both agent and service:
- **gRPC protos** — Wire format contracts
- **CloudEvents** — Event type definitions
- **Domain models** — `Finding`, `Scan`, `Alert` types
- **Version** — Single version constant for both binaries

## Versioning

Both binaries share the same version:
```bash
make release VERSION=1.0.0
```

This tags the release as `vigil-1.0.0` and builds both binaries with the same version string.

## Documentation

- `agent/CLAUDE.md` — Agent development guide
- `service/CLAUDE.md` — Service development guide
- `service/migrations/` — Database schema changes

## Deviation

Per root `CLAUDE.md` §32, Vigil intentionally deviates from the canonical service template and retains its pre-existing stack: **pgx/v5 with raw SQL (not GORM), Atlas migrations (not golang-migrate), and a Chi HTTP server** for its portal-facing REST surface. These predate the constitution and the portal depends on the Chi surface, so they are kept intact. As of the P13 seam, the `service` module **also serves gRPC** (`CodeAnalysisService`, `:50054`) alongside the Chi HTTP server so the delivery deploy gate and other internal callers (ops/git/foundry) can reach Vigil's scan surface machine-to-machine; the gRPC server uses a plain `grpc.NewServer` with recovery + OTel + logging interceptors (not the platform-kit `grpcserver`/mesh stack — Vigil is not a SPIFFE/mTLS mesh workload). Caller auth is the **shared platform internal service token via `x-api-key`** (`APP_INTERNAL_SERVICE_TOKEN`, constant-time compare, empty → trust in-cluster), mirroring catalog-service; because the plain server can't use platform-kit's full `NewChain` (which pulls the SVID/tenant/mesh stack Vigil isn't wired for), only the standalone `interceptor.UnaryAuth` is added after the local recovery + logging. On the homelab `APP_INTERNAL_SERVICE_TOKEN` is empty so callers (e.g. the delivery deploy gate) are trusted in-cluster; in prod a set value is enforced.

## License

Proprietary — Sentiae Inc.
