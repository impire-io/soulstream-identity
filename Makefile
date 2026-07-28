.PHONY: fmt tidy build test lint check

# Stamp the binary with a real version for local builds; goreleaser sets the tag
# on release. Override with `make build VERSION=x.y.z`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/impire-io/soulidentity/internal/version.Version=$(VERSION)

# Format all Go source (gofmt); golangci-lint's formatters also cover goimports.
fmt:
	gofmt -w .

# Keep go.mod/go.sum honest.
tidy:
	go mod tidy

build:
	go build ./...
	go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

# All tests, no skips.
test:
	go test ./...

lint:
	golangci-lint run

# The one gate to run before every commit: everything green.
check: fmt tidy build test lint
