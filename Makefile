.PHONY: build test lint clean sdk-test sdk-run

BINARY_NAME := epack-collector-github
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build the collector binary for the current platform
build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME) ./cmd/$(BINARY_NAME)

# Build for all platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME)-linux-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME)-linux-arm64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/$(BINARY_NAME)

# Run tests
test:
	go test -race -v ./...

# Lint code (downloads golangci-lint binary to match CI)
GOLANGCI_LINT_VERSION := v2.9.0
GOLANGCI_LINT := ./bin/golangci-lint

$(GOLANGCI_LINT):
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b ./bin $(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

# SDK development commands (requires epack with components build)
sdk-test: build
	epack sdk test ./$(BINARY_NAME)

sdk-run: build
	epack sdk run ./$(BINARY_NAME)
