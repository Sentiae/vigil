# Vigil — Unified Build System
# Product: Security & Infrastructure Intelligence Platform

.PHONY: all build-all test-all clean release

# Default target
all: build-all

# Build both binaries
build-all: build-agent build-service

build-agent:
	@echo "→ Building Vigil agent..."
	cd agent && go build -o ../bin/vigil-agent ./cmd/agent
	cd agent && go build -o ../bin/vigil-operator ./cmd/operator

build-service:
	@echo "→ Building Vigil service..."
	cd service && go build -o ../bin/vigil-server ./cmd/server
	cd service && go build -o ../bin/vigil-worker ./cmd/worker

# Test all components
test-all:
	@echo "→ Running tests..."
	cd agent && go test ./...
	cd service && go test ./...
	cd shared && go test ./...

# Lint all components
lint-all:
	@echo "→ Running linters..."
	cd agent && golangci-lint run
	cd service && golangci-lint run

# Clean build artifacts
clean:
	rm -rf bin/
	cd agent && go clean
	cd service && go clean
	cd shared && go clean

# Docker builds
docker-build-all: docker-build-agent docker-build-service

docker-build-agent:
	docker build -f agent/Dockerfile -t sentiae/vigil-agent:latest .

docker-build-service:
	docker build -f service/Dockerfile.service -t sentiae/vigil-service:latest .
	docker build -f service/Dockerfile.worker -t sentiae/vigil-worker:latest .

# Release (tag both binaries with same version)
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.0.0)
endif
	@echo "→ Releasing Vigil $(VERSION)..."
	git tag -a vigil-$(VERSION) -m "Vigil $(VERSION)"
	@echo "✓ Tagged as vigil-$(VERSION)"
