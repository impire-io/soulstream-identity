.PHONY: fmt tidy build test lint check

# Stamp the binary with a real version for local builds; goreleaser sets the tag
# on release. Override with `make build VERSION=x.y.z`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/impire-io/soulstream-identity/internal/version.Version=$(VERSION)

# Format all Go source (gofmt); golangci-lint's formatters also cover goimports.
fmt:
	gofmt -w .

# Keep go.mod/go.sum honest — the consumer-position e2e modules too.
tidy:
	go mod tidy
	cd e2e && go mod tidy
	cd e2e/embedgate && go mod tidy

build:
	go build ./...
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

# All tests, no skips — including the M2 cross-service proof in e2e/, a
# separate module in consumer position (it imports soulstream; this module
# never does — the cycle guard).
test:
	go test ./...
	cd e2e && go test ./...
	cd e2e/embedgate && go test ./...

lint:
	golangci-lint run
	cd e2e && golangci-lint run
	cd e2e/embedgate && golangci-lint run

# The one gate to run before every commit: everything green.
check: fmt tidy build test lint
