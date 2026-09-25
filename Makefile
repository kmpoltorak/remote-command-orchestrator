VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/kmpoltorak/remote-command-orchestrator/internal/cli.Version=$(VERSION)

.PHONY: build test race lint fmt check clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/rco ./cmd/rco

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

# Everything CI runs.
check:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	go test -race ./...
	go build ./...

clean:
	rm -rf bin
