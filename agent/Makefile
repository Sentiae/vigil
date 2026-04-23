# Makefile for code-analysis-agent (Vigil eBPF Agent)
APP_NAME := code-analysis-agent
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS  := -w -s -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

.PHONY: help
help: ## Show all available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the agent and operator binaries
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME) cmd/agent/main.go
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/vigil-operator cmd/operator/main.go

.PHONY: test
test: ## Run tests
	go test -race -timeout 5m ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run --timeout 5m

.PHONY: generate-ebpf
generate-ebpf: ## Generate Go bindings from eBPF C programs (requires bpf2go)
	go generate ./internal/ebpf/...

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
