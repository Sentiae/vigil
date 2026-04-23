# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /agent ./cmd/agent
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /operator ./cmd/operator

# Runtime stage — needs Linux capabilities for eBPF
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /agent /app/agent
COPY --from=builder /operator /app/operator

# eBPF requires specific Linux capabilities
# These are set at the DaemonSet level via securityContext

LABEL org.opencontainers.image.description="Code Analysis Agent (Vigil) — eBPF Runtime Monitor"

ENTRYPOINT ["/app/agent"]
