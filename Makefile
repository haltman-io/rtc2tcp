# rtc2tcp reproducible-build targets.
#
# The release workflow in .github/workflows/release.yml cross-compiles
# every supported platform with the same flags; this Makefile is the
# single source of truth for "what does a clean, reproducible build look
# like on your own machine?"

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

# -s -w drops the symbol and DWARF tables; -trimpath drops absolute
# paths from the embedded file references. Both are required for a
# bit-identical build across build hosts.
LDFLAGS := -s -w \
	-X github.com/haltman-io/rtc2tcp/internal/config.Version=$(VERSION) \
	-X github.com/haltman-io/rtc2tcp/internal/config.Commit=$(COMMIT)

GOFLAGS := -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all broker peer test race vet fmt tidy clean

all: broker peer

broker:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/rtc2tcp-broker ./cmd/rtc2tcp-broker

peer:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/rtc2tcp-peer ./cmd/rtc2tcp-peer

test:
	go test ./... -timeout 2m

race:
	CGO_ENABLED=1 go test ./... -race -timeout 5m

vet:
	go vet ./...

fmt:
	gofmt -l . | tee /dev/stderr | (! read -r)

tidy:
	go mod tidy
	git diff --quiet -- go.mod go.sum

clean:
	rm -rf bin dist
