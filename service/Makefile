# Makefile for code-analysis-service (Vigil)
# =============================================================================
# Service-specific configuration
# =============================================================================
APP_NAME     := code-analysis-service
DOCKER_IMAGE := code-analysis-service:latest
DATABASE_URL := postgres://postgres:postgres@localhost:5432/code_analysis_service?sslmode=disable
ATLAS_ENV    := local

# Docker: uses parent dir as build context (for local replace directives)
DOCKER_BUILD_CONTEXT := ..
DOCKER_BUILD_FILE    := Dockerfile

# Include shared platform-kit targets
PLATFORM_KIT_DIR := $(shell cd ../.. && pwd)/platform-kit
include $(PLATFORM_KIT_DIR)/Makefile.include

# =============================================================================
# Code-analysis-specific targets
# =============================================================================

.PHONY: build-worker
build-worker: ## Build the scanner worker binary
	go build -ldflags "$(LDFLAGS)" -o bin/worker cmd/worker/main.go

.PHONY: run-worker
run-worker: ## Run the scanner worker locally
	go run cmd/worker/main.go

.PHONY: docker-build-worker
docker-build-worker: ## Build the scanner worker Docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-f Dockerfile.worker \
		-t $(APP_NAME)-worker:$(VERSION) \
		-t $(APP_NAME)-worker:latest \
		$(DOCKER_BUILD_CONTEXT)
