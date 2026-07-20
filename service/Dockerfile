# syntax=docker/dockerfile:1.6

# ===========================================================================
# Stage 1 — Build the control plane Go binary.
# ===========================================================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

# Repo-root build context (compose: context: .).
WORKDIR /src/vigil/service

# Copy go.mod and go.sum first for better caching
COPY vigil/service/go.mod vigil/service/go.sum ./
# Fetch platform-kit (and everything else) through the Athens Go proxy — the
# single source of truth. No ",direct" fallback: a proxy miss must FAIL rather
# than silently fall back to direct git (which would re-expose the drift the
# substrate forbids). GOPRIVATE/GONOPROXY left UNSET so all sentiae modules
# route through Athens by construction; GONOSUMDB scopes the checksum-DB skip to
# the private module (platform-kit is verified against the committed go.sum).
ARG GOPROXY
ARG GOFLAGS
ENV GOPROXY=${GOPROXY} \
    GOFLAGS=${GOFLAGS} \
    GONOSUMDB=github.com/sentiae/* \
    GOTOOLCHAIN=auto
RUN go mod download

# Copy source code
COPY vigil/service/ .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

# ===========================================================================
# Stage 2 — Runtime image. Lean: this control-plane serves HTTP + the P13
# gRPC security seam + drains the outbox; it runs no scanners and needs no
# language toolchain. The SCIP code-intelligence indexers (scip-go/-ts/
# -python/-rust) were dropped here — they belong to the code-intelligence
# annex (not the SEC-04 security gate) and are currently broken upstream
# (sourcegraph/scip module renames + replace-directive install failures).
# Restore them when the code-intelligence annex is built.
# ===========================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
 && rm -rf /var/lib/apt/lists/*

# App binary + configs.
WORKDIR /app
COPY --from=builder /server /app/server
COPY --from=builder /src/vigil/service/configs /app/configs

# Drop to an unprivileged account.
RUN groupadd --system --gid 65532 sentiae \
 && useradd  --system --uid 65532 --gid sentiae --home /app --shell /usr/sbin/nologin sentiae \
 && chown -R sentiae:sentiae /app

USER sentiae:sentiae

EXPOSE 8091 50054

LABEL org.opencontainers.image.description="Vigil control plane — security findings + P13 CodeAnalysisService (SEC-04 gate)"
LABEL org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/app/server"]
