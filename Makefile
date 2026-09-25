VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/kmpoltorak/remote-command-orchestrator/internal/cli.Version=$(VERSION)

# Release targets: Linux (incl. 32-bit ARM for older Raspberry Pi) and macOS.
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64

.PHONY: build test race lint vuln fmt check release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/rco ./cmd/rco

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run

# Known vulnerabilities in dependencies and the Go toolchain that our code actually calls.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fmt:
	gofmt -w .

# Everything CI runs.
check:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	go test -race ./...
	go build ./...

# dist/rco_<version>_<os>_<arch>.tar.gz (binary + README + LICENSE) and checksums.txt
release:
	rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; [ $$arch = arm ] && label=armv7 || label=$$arch; \
		name=rco_$(VERSION)_$${os}_$${label}; \
		echo "building $$name"; \
		GOOS=$$os GOARCH=$$arch GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/rco ./cmd/rco || exit 1; \
		cp README.md LICENSE dist/$$name/ && tar -C dist -czf dist/$$name.tar.gz $$name && rm -rf dist/$$name; \
	done
	cd dist && (command -v sha256sum >/dev/null && sha256sum *.tar.gz || shasum -a 256 *.tar.gz) > checksums.txt

clean:
	rm -rf bin dist
