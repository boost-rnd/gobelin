.PHONY: help lint test build clean

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1)
	golangci-lint run ./...

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build: ## Build the binary
	go build -o gobelin .

clean: ## Clean build artifacts
	rm -f gobelin coverage.out

all: lint test build ## Run lint, test, and build
