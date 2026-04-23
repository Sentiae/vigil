# Code Analysis Service (Vigil) — Service Reference

This service provides full-stack security and infrastructure intelligence analysis for the Sentiae Agent Platform. Product name: **Vigil**.

## Directory Layout

```
code-analysis-service/
├── cmd/
│   ├── server/main.go              # Control plane entry point
│   └── worker/main.go              # Scanner worker entry point (asynq)
├── internal/
│   ├── app/                        # Server bootstrap & DI container
│   │   ├── container.go            # Wires repos -> usecases -> handlers
│   │   └── server.go               # HTTP (Chi) server lifecycle
│   ├── domain/                     # Pure business models, errors, validation
│   ├── port/                       # Interface definitions (hexagonal ports)
│   │   ├── repository/             # Repository interfaces
│   │   ├── usecase/                # Use case interfaces
│   │   ├── gateway/                # External service interfaces
│   │   └── scanner/                # Scanner module interface
│   ├── usecase/                    # Business logic services
│   ├── adapter/                    # Interface implementations (hexagonal adapters)
│   │   ├── handler/
│   │   │   ├── http/               # REST handlers (Chi)
│   │   │   ├── grpc/               # gRPC handlers (agent communication)
│   │   │   └── event/              # Kafka consumer handlers
│   │   ├── repository/
│   │   │   ├── postgres/           # pgx/v5 repositories (NOT GORM)
│   │   │   ├── clickhouse/         # ClickHouse analytics layer
│   │   │   ├── neo4j/              # Neo4j graph layer
│   │   │   └── redis/              # Cache layer
│   │   ├── gateway/                # External service clients
│   │   └── scanner/                # Scanner module implementations
│   ├── middleware/                  # HTTP middleware (auth, etc.)
│   └── constants/
├── pkg/
│   ├── config/                     # Viper-based configuration
│   ├── events/                     # Kafka event publishing (CloudEvents 1.0)
│   ├── logger/                     # Structured logging (slog + OpenTelemetry)
│   ├── telemetry/                  # OpenTelemetry tracing + Prometheus metrics
│   ├── database/                   # pgx/v5 + ClickHouse + Neo4j connections
│   └── storage/                    # S3/MinIO client
├── migrations/                     # Atlas SQL migrations (PostgreSQL)
├── configs/config.yaml             # Default configuration
├── proto/security/v1/              # Protobuf definitions (agent gRPC)
├── Dockerfile                      # Lean control plane image
├── Dockerfile.worker               # Fat scanner worker (bundles Trivy, Semgrep, etc.)
├── docker-compose.yml              # Local dev
└── Makefile                        # Build targets (includes platform-kit)
```

## Key Differences from identity-service

- **Database driver**: pgx/v5 (NOT GORM). Raw SQL queries. No auto-migrate — uses Atlas migrations.
- **Multi-store**: PostgreSQL (OLTP) + ClickHouse (analytics) + Neo4j (graph) + Redis (cache/queue)
- **Two binaries**: `cmd/server/` (control plane) and `cmd/worker/` (scanner worker with asynq)
- **Scanner modules**: 11 independent scanner modules in `internal/adapter/scanner/`

## Dependency Direction Rules

Same as identity-service — dependencies flow inward only:
```
handler/gateway -> usecase -> domain
adapter/repository -> port/repository (implements interface)
adapter/scanner -> port/scanner (implements interface)
adapter/handler -> port/usecase (depends on interface)
```

## How to Add a New Scanner Module

1. Create directory `internal/adapter/scanner/{module}/`
2. Implement the `Scanner` interface from `internal/port/scanner/scanner.go`
3. Register in the scanner registry (`internal/adapter/scanner/registry.go`)
4. Add asynq task handler in `cmd/worker/main.go`

## Ports

| Service | Host Port | Internal Port | Protocol |
|---------|-----------|---------------|----------|
| HTTP API | 8091 | 8080 | HTTP |
| gRPC (agents) | 50054 | 50054 | gRPC |

## Data Stores

| Store | Purpose | Driver |
|-------|---------|--------|
| PostgreSQL 16 | Primary OLTP (findings, scans, assets, policies) | pgx/v5 |
| ClickHouse | Analytics, time-series, full-text search | clickhouse-go/v2 |
| Neo4j | Asset graph, blast radius, attack paths | neo4j-go-driver |
| Redis 7 | Cache, rate limiting, asynq task queue | go-redis/v9 |
| MinIO/S3 | SARIF, SBOM, compliance PDF artifacts | aws-sdk-go-v2 |

## Kafka Events

Topic: `sentiae.security.events`
12 event types — see `pkg/events/events.go`

## Build

```
make build              # Build server binary
make build-worker       # Build worker binary
make test               # Run unit tests
make lint               # golangci-lint
make docker-build       # Build control plane image
make docker-build-worker # Build scanner worker image
```
