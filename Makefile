BINARY     := s3sentinel
CMD        := ./cmd/s3sentinel
BUILD_DIR  := .

# Go toolchain
GO         := go
GOFLAGS    ?=

# Docker
IMAGE_NAME ?= s3sentinel
IMAGE_TAG  ?= dev

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' \
		| sort

.PHONY: build
build: ## Build the binary
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)

.PHONY: build-linux
build-linux: ## Cross-compile a static Linux binary (for Docker)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)

.PHONY: clean
clean: ## Remove build artefacts
	rm -f $(BUILD_DIR)/$(BINARY)

.PHONY: run
run: ## Run the proxy (reads .env if present)
	@if [ -f .env ]; then \
		set -a && . ./.env && set +a && $(GO) run $(CMD); \
	else \
		$(GO) run $(CMD); \
	fi

.PHONY: test
test: ## Run all tests
	$(GO) test ./...

.PHONY: test-verbose
test-verbose: ## Run all tests with verbose output
	$(GO) test -v ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Generate and display a coverage report
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all Go source files
	$(GO) fmt ./...

.PHONY: lint
lint: ## Run golangci-lint (install: https://golangci-lint.run/usage/install/)
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run golangci-lint and apply auto-fixes
	golangci-lint run --fix ./...

.PHONY: check-dirty
check-dirty:
	./scripts/check-dirty.sh

.PHONY: check
check: vet test lint ## Run vet + tests + lint (CI gate)

.PHONY: tidy
tidy: ## Tidy and verify go.mod / go.sum
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: download
download: ## Download all module dependencies
	$(GO) mod download

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: docker-run
docker-run: ## Run the Docker image (reads .env if present)
	docker run --rm --env-file .env \
		-p 8080:8080 -p 8090:8090 -p 9090:9090 \
		$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: up
up: ## Start the local dev stack (OPA + Zitadel) via docker-compose
	docker compose -f examples/basic/docker-compose.yml up -d

.PHONY: down
down: ## Stop the local dev stack
	docker compose -f examples/basic/docker-compose.yml down

.PHONY: logs
logs: ## Tail logs from the local dev stack
	docker compose -f examples/basic/docker-compose.yml logs -f

.PHONY: opa-run
opa-run: ## Start OPA locally, serving the policy/ directory
	opa run --server --addr :8181 policy/

.PHONY: opa-check
opa-check: ## Validate and type-check all .rego files
	opa check policy/

.PHONY: gen-sts-secret
gen-sts-secret: ## Generate a random 32-byte HMAC key for STS_TOKEN_SECRET
	@echo "STS_TOKEN_SECRET=$$(openssl rand -hex 32)"
