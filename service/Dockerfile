# syntax=docker/dockerfile:1.6

# ===========================================================================
# Stage 1 — Build the control plane Go binary.
# ===========================================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

ARG GITHUB_TOKEN
ENV GOPRIVATE=github.com/sentiae/*
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

WORKDIR /app

# Copy platform-kit (local replace dependency)
COPY platform-kit/ /platform-kit/

# Copy go.mod and go.sum first for better caching
COPY code-analysis-service/go.mod code-analysis-service/go.sum ./
RUN go mod download

# Copy source code
COPY code-analysis-service/ .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

# scip CLI (proto manipulation) is compiled out-of-module so it does not
# pollute go.mod. GOBIN=/out forces a known output path the next stage
# can COPY from.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    GOBIN=/out CGO_ENABLED=0 GOOS=linux go install github.com/sourcegraph/scip/cmd/scip@latest \
 && mv /out/scip /scip

# ===========================================================================
# Stage 2 — Pre-compile scip-go so the final image does not need a Go
# toolchain. The produced binary is CGO-free and can be copied into the
# distroless-style final stage.
# ===========================================================================
FROM golang:1.25-alpine AS scip-go-builder
RUN apk add --no-cache git ca-certificates
RUN CGO_ENABLED=0 go install github.com/sourcegraph/scip-go/cmd/scip-go@latest

# ===========================================================================
# Stage 3 — Runtime image. Built on debian-slim so we can install Node
# (for scip-typescript) and Python (for scip-python); distroless would
# cost us that. We still run as a non-root user and only install the
# packages actually needed to produce a SCIP index or serve HTTP/gRPC.
# ===========================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        python3 \
        python3-pip \
        python3-venv \
        nodejs \
        npm \
        xz-utils \
 && rm -rf /var/lib/apt/lists/*

# --- scip-typescript: canonical NPM distribution, pinned to latest.
RUN npm install -g @sourcegraph/scip-typescript \
 && ln -sf /usr/bin/scip-typescript /usr/local/bin/scip-typescript

# --- scip-python: canonical PyPI distribution.
RUN pip3 install --break-system-packages --no-cache-dir scip-python

# --- scip-go + scip (proto tool) come from the Go builder stages.
COPY --from=scip-go-builder /go/bin/scip-go /usr/local/bin/scip-go
COPY --from=builder /scip /usr/local/bin/scip

# --- scip-rust: rust-analyzer ships the official `rust-analyzer scip`
# subcommand which emits the same index.scip proto shape. We install
# the static binary from the official GitHub release — no cargo needed.
ARG RUST_ANALYZER_VERSION=2024-12-30
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) ra_target="x86_64-unknown-linux-gnu" ;; \
      arm64) ra_target="aarch64-unknown-linux-gnu" ;; \
      *) echo "unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/rust-lang/rust-analyzer/releases/download/${RUST_ANALYZER_VERSION}/rust-analyzer-${ra_target}.gz" -o /tmp/ra.gz; \
    gunzip -c /tmp/ra.gz > /usr/local/bin/rust-analyzer; \
    rm -f /tmp/ra.gz; \
    chmod +x /usr/local/bin/rust-analyzer; \
    # Thin shim so the Go indexer's `scip-rust` lookup resolves to the
    # rust-analyzer subcommand. Accepts an `index` argument for symmetry
    # with the other scip-* CLIs.
    printf '#!/bin/sh\nexec /usr/local/bin/rust-analyzer scip "$@"\n' > /usr/local/bin/scip-rust; \
    chmod +x /usr/local/bin/scip-rust

# Sanity check — the build fails loudly if any indexer is missing.
RUN which scip-typescript scip-python scip-go scip-rust scip

# App binary + configs.
WORKDIR /app
COPY --from=builder /server /app/server
COPY --from=builder /app/configs /app/configs

# Drop to an unprivileged account.
RUN groupadd --system --gid 65532 sentiae \
 && useradd  --system --uid 65532 --gid sentiae --home /app --shell /usr/sbin/nologin sentiae \
 && chown -R sentiae:sentiae /app

USER sentiae:sentiae

EXPOSE 8080 50054

LABEL org.opencontainers.image.source="https://github.com/sentiae/code-analysis-service"
LABEL org.opencontainers.image.description="Code Analysis Service (Vigil) — SCIP-bundled"
LABEL org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/app/server"]
